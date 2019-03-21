'use strict';

const log = require('npmlog');
const util = require('util');
const tokens = require('./tokens');
const gravatarUrl = require('gravatar-url');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const csrf = require('csurf');
const apiClient = require('./api-client');

module.exports.csrf = csrf({
    cookie: true
});

module.exports.setup = app => {
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports.logout = (req, res) => {
    if (req.user) {
        req.flash('success', util.format('%s  logged out', req.user.name || req.user.username));
        req.logout();
    }
    res.redirect('/');
};

module.exports.login = (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            log.error('Passport', 'AUTHFAIL username=%s error=%s', req.body.username, err.message);
            req.flash('danger', 'Authentication error');
            return next(err);
        }
        if (!user) {
            req.flash('danger', (info && info.message) || 'Failed to authenticate user');
            return res.redirect('/account/login');
        }
        req.logIn(user, err => {
            if (err) {
                return next(err);
            }

            if (req.body.remember) {
                // Cookie expires after 30 days
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            } else {
                // Cookie expires at end of session
                req.session.cookie.expires = false;
            }

            // remember used username as it might differ from actual value
            req.session.username = req.body.username;

            if (req.body._2faToken && req.session.require2fa && tokens.checkToken(user.id, req.body._2faToken, tokens.TOKEN_2FA)) {
                req.session.require2fa = false;
            }

            if (!req.session.require2fa) {
                req.flash('success', util.format('Logged in as %s', user.username));

                // temporary value that indicates successful login and allows to use account recovery in the future
                req.session.successlog = {
                    username: req.body.username,
                    value: tokens.generateToken(req.user.id, tokens.TOKEN_RECOVERY)
                };
            }

            apiClient.mailboxes.list(req.user, true, (err, mailboxes) => {
                if (err) {
                    req.flash('danger', err.message);
                    res.redirect('/webmail');
                    return;
                }

                let inbox = mailboxes.find(box => box.path === 'INBOX');
                req.session.inbox = inbox ? inbox.id : false;

                return res.redirect('/webmail');
            });
        });
    })(req, res, next);
};

module.exports.checkLogin = (req, res, next) => {
    if (!req.user) {
        return res.redirect('/account/login');
    }
    next();
};

passport.use(
    new LocalStrategy(
        {
            passReqToCallback: true
        },
        (req, username, password, done) => {
            req.session.regenerate(() => {
                apiClient.users.authenticate(username, password, req.session.id, req.ip, (err, user) => {
                    if (err) {
                        return done(err);
                    }

                    if (!user) {
                        return done(null, false, {
                            message: 'Incorrect username or password'
                        });
                    }

                    req.session.require2fa = user.require2fa;
                    req.session.requirePasswordChange = user.requirePasswordChange;

                    delete user.require2fa;
                    delete user.requirePasswordChange;
                    done(null, user);
                });
            });
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, JSON.stringify(user));
});

passport.deserializeUser((user, done) => {
    let data = null;
    try {
        data = JSON.parse(user);
    } catch (err) {
        //ignore
        err.resetSession = true;
        return done(err);
    }

    apiClient.users.get(data, (err, userData) => {
        if (err) {
            err.resetSession = true;
            return done(err);
        }
        if (!userData) {
            return done();
        }
        userData.token = data.token;
        apiClient.mailboxes.get(userData, 'resolve', { path: 'INBOX' }, (err, inboxData) => {
            if (err) {
                err.resetSession = true;
                return done(err);
            }
            userData.gravatar = gravatarUrl(userData.address || userData.username, {
                size: 20,
                // 404, mm, identicon, monsterid, wavatar, retro, blank
                default: 'identicon'
            });
            userData.inbox = inboxData;
            done(null, userData);
        });
    });
});

'use strict';

const config = require('wild-config');
const log = require('npmlog');
const util = require('util');
const crypto = require('crypto');

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
        req.flash('info', util.format('%s  logged out', req.user.username));
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

            if (req.body._2faToken && req.session.require2fa && check2faRemeberToken(user.id, req.body._2faToken)) {
                req.session.require2fa = false;
            }

            if (!req.session.require2fa) {
                req.flash('success', util.format('Logged in as %s', user.username));
            }

            return res.redirect('/webmail');
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
                    delete user.require2fa;
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
    } catch (E) {
        //ignore
    }
    done(null, data);
});

function check2faRemeberToken(user, token) {
    let parts = token.split('::');
    let hash = parts.pop();
    let timestamp = parseInt(parts[0], 16);

    if (timestamp < Date.now() - 30 * 24 * 3600 * 1000) {
        return false;
    }

    return (
        hash ===
        crypto
            .createHmac('sha256', config.totp.secret + ':' + user)
            .update(parts.join('::'))
            .digest('hex')
    );
}

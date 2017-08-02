'use strict';

const config = require('wild-config');
const log = require('npmlog');
const util = require('util');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const csrf = require('csurf');
const bodyParser = require('body-parser');
const apiClient = require('./api-client');

module.exports.parse = bodyParser.urlencoded({
    extended: false,
    limit: config.www.postsize
});

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

            req.flash('success', util.format('Logged in as %s', user.username));
            return res.redirect('/account/');
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
            apiClient.users.authenticate(username, password, req.ip, (err, user) => {
                if (err) {
                    return done(err);
                }

                if (!user) {
                    return done(null, false, {
                        message: 'Incorrect username or password'
                    });
                }

                req.session.regenerate(() => {
                    req.session.require2fa = !!user.require2fa;
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

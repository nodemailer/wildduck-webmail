'use strict';

const config = require('wild-config');
const gravatarUrl = require('gravatar-url');
const apiClient = require('./api-client');

const getUserId = (req, res, done) => {
    let username = (req.headers[config.service.sso.http.header.toLowerCase()] || '').trim();
    if (!username) {
        // no username set
        return done(null, false);
    }

    if (req.session.ssoHttpUserName !== username) {
        // username has changed or set, resolve actual user
        return apiClient.users.resolve({ username, ip: req.ip, sess: req.session.id }, (err, result) => {
            if (err) {
                return done(err);
            }

            if (!result) {
                // unknown username
                return done(null, false);
            }

            req.session.ssoHttpUserName = username;
            req.session.ssoHttpUserId = result.id;

            return done(null, result.id);
        });
    }

    return done(null, req.session.ssoHttpUserId);
};

const setup = app => {
    app.use((req, res, next) => {
        res.locals.ssoEnabled = config.service.sso.http.enabled;

        getUserId(req, res, (err, id) => {
            if (err) {
                return next(err);
            }

            if (!id) {
                req.session.ssoHttpUserId = '';
                return req.session.save(() => {
                    res.redirect(config.service.sso.http.authRedirect);
                });
            }

            apiClient.users.get({ id, ip: req.ip, sess: req.session.id }, (err, userData) => {
                if (err) {
                    err.resetSession = true;
                    return next(err);
                }

                if (!userData) {
                    return req.session.save(() => {
                        res.redirect(config.service.sso.http.authRedirect);
                    });
                }

                apiClient.mailboxes.get(userData, 'resolve', { path: 'INBOX' }, (err, inboxData) => {
                    if (err) {
                        err.resetSession = true;
                        return next(err);
                    }

                    userData.gravatar = gravatarUrl(userData.address || userData.username, {
                        size: 20,
                        // 404, mm, identicon, monsterid, wavatar, retro, blank
                        default: 'identicon'
                    });

                    userData.inbox = inboxData;
                    req.user = userData;
                    next();
                });
            });
        });
    });
};

module.exports = { setup };

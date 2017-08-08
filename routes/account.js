'use strict';

const config = require('wild-config');
const express = require('express');
const router = new express.Router();
const passport = require('../lib/passport');
const Joi = require('joi');
const apiClient = require('../lib/api-client');
const roleBasedAddresses = require('role-based-email-addresses');
const util = require('util');
const humanize = require('humanize');

// sub services
router.use('/filters', passport.checkLogin, require('./account/filters'));
router.use('/autoreply', passport.checkLogin, require('./account/autoreply'));

router.get('/', passport.csrf, passport.checkLogin, (req, res, next) => {
    apiClient.users.get(req.user.id, (err, userData) => {
        if (err) {
            return next(err);
        }

        res.render('account/index', {
            activeHome: true,

            address: userData.address,

            quota: humanize.filesize(userData.limits.quota.allowed),
            storageUsed: humanize.filesize(userData.limits.quota.used),
            storageOverview: Math.round(userData.limits.quota.used / userData.limits.quota.allowed * 100),

            recipients: humanize.numberFormat(userData.limits.recipients.allowed, 0),
            recipientsSent: humanize.numberFormat(userData.limits.recipients.used, 0),
            recipientsOverview: Math.round(userData.limits.recipients.used / (userData.limits.recipients.allowed || 1) * 100),

            forwards: humanize.numberFormat(userData.limits.forwards.allowed, 0),
            forwardsSent: humanize.numberFormat(userData.limits.forwards.used, 0),
            forwardsOverview: Math.round(userData.limits.forwards.used / (userData.limits.forwards.allowed || 1) * 100)
        });
    });
});

router.get('/security/logins', (req, res, next) => {
    const updateSchema = Joi.object().keys({
        next: Joi.string().max(100).empty(''),
        previous: Joi.string().max(100).empty(''),
        page: Joi.number().empty('')
    });

    let result = Joi.validate(req.query, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/account/security/logins');
    }

    apiClient.asps.list(req.user.id, (err, asps) => {
        if (err) {
            return next(err);
        }

        let aspsmap = new Map();
        asps.forEach(asp => {
            aspsmap.set(asp.id, asp);
        });

        apiClient.authlog.list(req.user.id, { next: req.query.next, previous: req.query.previous, page: result.value.page || 1 }, (err, log) => {
            if (err) {
                return next(err);
            }
            log.nextPage = log.page + 1;
            log.previousPage = Math.max(log.page - 1, 1);
            log.results.forEach(entry => {
                if (entry.asp) {
                    entry.asp = aspsmap.get(entry.asp) || { description: '[unknown ' + entry.asp + ']' };
                }
                entry.showCount = entry.count && entry.count > 1;
            });
            res.render('account/security/logins', log);
        });
    });
});

router.get('/logout', (req, res) => {
    req.session.require2fa = false;
    req.flash(); // clear pending messages
    passport.logout(req, res);
});

router.post('/login', passport.parse, (req, res, next) => passport.login(req, res, next));

router.get('/login', (req, res) => {
    res.render('account/login', {
        activeLogin: true
    });
});

router.get('/create', passport.csrf, (req, res) => {
    res.render('account/create', {
        title: 'Create new account',
        activeCreate: true,
        csrfToken: req.csrfToken()
    });
});

router.post('/create', passport.parse, passport.csrf, (req, res) => {
    const createSchema = {
        name: Joi.string().trim().min(3).max(100).label('Your name').required(),
        password: Joi.string()
            .min(8)
            .max(100)
            .label('Password')
            .valid(Joi.ref('password2'))
            .options({
                language: {
                    any: {
                        allowOnly: '!!Passwords do not match'
                    }
                }
            })
            .required(),

        language: Joi.string().length(2).default('en'),
        password2: Joi.string().min(8).max(100).label('Password confirmation').required(),
        username: Joi.string().trim().min(3).max(128).hostname().lowercase().label('Address').required()
    };

    delete req.body._csrf;
    let result = Joi.validate(req.body, createSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false,
        language: {
            string: {
                min: '"{{!key}}" length must be at least {{limit}} characters long',
                max: '"{{!key}}" length must be less than or equal to {{limit}} characters',
                hostname: '"{{!key}}" must be a valid email user part'
            },
            object: {
                assert: '!!Passwords do not match'
            }
        }
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Failed creating account');
        }
        res.render('account/create', {
            title: 'Create new account',
            values: result.value,
            errors,
            activeCreate: true,
            csrfToken: req.csrfToken()
        });
    };

    if (result.error) {
        let errors = {};

        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                if (!errors[detail.path]) {
                    errors[detail.path] = detail.message;
                }
            });
        }

        return showErrors(errors);
    }

    if (
        ['abuse', 'admin', 'administrator', 'hostmaster', 'majordomo', 'postmaster', 'root', 'ssl-admin', 'webmaster'].includes(result.value.username) ||
        roleBasedAddresses.includes(result.value.username)
    ) {
        return showErrors({
            username: util.format('"%s" is a reserved username', result.value.username)
        });
    }

    apiClient.users.create(
        {
            name: result.value.name,
            username: result.value.username,
            password: result.value.password,
            address: result.value.username + '@' + config.service.domain,
            recipients: 500,
            forwards: 500,
            quota: 1 * 1024 * 1024 * 1024,
            ip: req.ip
        },
        err => {
            if (err) {
                if (err.fields) {
                    return showErrors(err.fields);
                } else {
                    req.flash('danger', err.message);
                    return showErrors({}, true);
                }
            }

            req.flash('success', 'Account created for ' + result.value.username + ' with address ' + result.value.username + '@' + config.service.domain);
            res.redirect('/account/login/');
        }
    );
});

router.get('/security', passport.csrf, passport.checkLogin, (req, res, next) => {
    apiClient.users.get(req.user.id, (err, userData) => {
        if (err) {
            return next(err);
        }
        apiClient.asps.list(req.user.id, (err, asps) => {
            if (err) {
                return next(err);
            }
            res.render('account/security', {
                title: 'Security',
                activeSecurity: true,
                values: req.user,

                csrfToken: req.csrfToken(),
                enabled2fa: userData.enabled2fa,
                asps: asps.reverse().map((entry, i) => {
                    entry.index = i + 1;

                    entry.scope = entry.scopes.includes('*') ? 'All' : entry.scopes.join(', ');
                    return entry;
                })
            });
        });
    });
});

router.get('/profile', passport.csrf, passport.checkLogin, (req, res, next) => {
    apiClient.users.get(req.user.id, (err, userData) => {
        if (err) {
            return next(err);
        }

        res.render('account/profile', {
            title: 'Account',
            activeProfile: true,
            values: userData,
            csrfToken: req.csrfToken()
        });
    });
});

router.post('/profile', passport.parse, passport.csrf, passport.checkLogin, (req, res) => {
    const updateSchema = Joi.object()
        .keys({
            name: Joi.string().empty('').max(100).label('Your name'),

            forward: Joi.string().empty('').email().label('Forward address'),
            targetUrl: Joi.string()
                .trim()
                .uri({
                    scheme: ['http', 'https'],
                    allowRelative: false,
                    relativeOnly: false
                })
                .empty('')
                .label('Upload URL'),

            pubKey: Joi.string().empty('').trim().regex(/^-----BEGIN PGP PUBLIC KEY BLOCK-----/, 'PGP key format'),
            encryptMessages: Joi.boolean().truthy(['Y', 'true', 'yes', 1]).default(false),

            existingPassword: Joi.string().empty('').min(8).max(100).label('Current password'),
            password: Joi.string().empty('').min(8).max(100).label('New password').valid(Joi.ref('password2')).options({
                language: {
                    any: {
                        allowOnly: '!!Passwords do not match'
                    }
                }
            }),
            password2: Joi.string().empty('').min(8).max(100).label('Repeat password')
        })
        .and('password', 'existingPassword', 'password2');

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false,

        language: {
            string: {
                min: '"{{!key}}" length must be at least {{limit}} characters long',
                max: '"{{!key}}" length must be less than or equal to {{limit}} characters',
                hostname: '"{{!key}}" must be a valid email user part'
            },
            object: {
                assert: '!!Passwords do not match'
            }
        }
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Account update failed');
        }

        res.render('account/profile', {
            title: 'Account',
            activeProfile: true,
            values: result.value,
            errors,

            csrfToken: req.csrfToken()
        });
    };

    if (result.error) {
        let errors = {};
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                let path = detail.path;
                if (detail.path === 'value') {
                    path = 'existingPassword';
                }
                if (!errors[path]) {
                    errors[path] = detail.message;
                }
            });
        }

        return showErrors(errors);
    }

    delete result.value.password2;
    result.value.name = result.value.name || '';
    result.value.forward = result.value.forward || '';
    result.value.targetUrl = result.value.targetUrl || '';
    result.value.pubKey = result.value.pubKey || '';

    result.value.ip = req.ip;

    apiClient.users.update(req.user.id, result.value, err => {
        if (err) {
            if (err.fields) {
                return showErrors(err.fields);
            } else {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }
        }

        req.flash('success', 'Updated account data for ' + req.user.username);
        res.redirect('/account/profile/');
    });
});

router.post('/asp/delete', passport.parse, passport.csrf, passport.checkLogin, (req, res) => {
    const updateSchema = Joi.object().keys({
        id: Joi.string().trim().hex().length(24).label('Password ID').required()
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/account/security');
    }

    apiClient.asps.del(req.user.id, result.value.id, req.ip, err => {
        if (err) {
            req.flash('danger', 'Database Error, failed to delete data');
            return res.redirect('/account/security');
        }

        req.flash('success', 'Application specific password was deleted');
        return res.redirect('/account/security');
    });
});

router.post('/asp/create', passport.parse, passport.csrf, passport.checkLogin, (req, res) => {
    const updateSchema = Joi.object().keys({
        description: Joi.string().trim().min(0).max(256).label('Description').required()
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/account/security');
    }

    let data = {
        description: result.value.description,
        scopes: '*',
        generateMobileconfig: true,
        ip: req.ip
    };

    apiClient.asps.create(req.user.id, data, (err, response) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/security');
        }

        res.render('account/asp', {
            layout: 'layout-popup',
            description: result.value.description,
            password: response.password,
            mobileconfig: response.mobileconfig,
            csrfToken: req.csrfToken(),
            passwordFormatted: response.password.replace(/.{4}/g, '$& ').trim()
        });
    });
});

router.post('/2fa', passport.parse, passport.csrf, (req, res) => {
    if (!req.user) {
        return res.redirect('/account/login');
    }

    const authSchema = Joi.object().keys({
        token: Joi.string().length(6).regex(/^[0-9]+$/, 'numbers').required()
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, authSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = errors => {
        res.render('account/2fa', {
            layout: 'layout-popup',
            title: 'Two factor authentication',
            csrfToken: req.csrfToken(),
            activeLogin: true,
            errors
        });
    };

    if (result.error) {
        let errors = {};
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                let path = detail.path;
                if (!errors[path]) {
                    errors[path] = detail.message;
                }
            });
        }

        return showErrors(errors);
    }

    apiClient['2fa'].check(req.user.id, result.value.token, req.ip, (err, result) => {
        if (!err && result) {
            req.session.require2fa = false;
            return res.redirect('/account/');
        }

        showErrors(
            {
                token: err.message
            },
            true
        );
    });
});

router.post('/enable-2fa', passport.parse, passport.csrf, passport.checkLogin, (req, res, next) => {
    const authSchema = Joi.object().keys({
        token: Joi.string().length(6).regex(/^[0-9]+$/, 'numbers')
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, authSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = errors => {
        apiClient['2fa'].setup(req.user.id, config.name, false, req.ip, (err, data) => {
            if (err) {
                return next(err);
            }
            res.render('account/enable-2fa', {
                layout: 'layout-popup',
                title: 'Two factor authentication',
                activeSecurity: true,
                csrfToken: req.csrfToken(),
                imageUrl: data.qrcode,
                activeLogin: true,
                errors
            });
        });
    };

    if (result.error) {
        let errors = {};
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                let path = detail.path;
                if (!errors[path]) {
                    errors[path] = detail.message;
                }
            });
        }

        return showErrors(errors);
    }

    if (result.value.token) {
        return apiClient['2fa'].verify(req.user.id, result.value.token, req.ip, err => {
            if (err) {
                return showErrors(
                    {
                        token: 'Check failed, try again'
                    },
                    true
                );
            }
            req.session.require2fa = false;
            req.flash('success', 'Two factor authentication is now enabled for your account');
            res.redirect('/account/security');
        });
    }

    apiClient['2fa'].setup(req.user.id, config.name, true, req.ip, (err, data) => {
        if (err) {
            return next(err);
        }
        res.render('account/enable-2fa', {
            layout: 'layout-popup',
            title: 'Two factor authentication',
            activeSecurity: true,
            csrfToken: req.csrfToken(),
            imageUrl: data.qrcode
        });
    });
});

router.post('/disable-2fa', passport.parse, passport.csrf, passport.checkLogin, (req, res, next) => {
    apiClient['2fa'].disable(req.user.id, req.ip, err => {
        if (err) {
            return next(err);
        }
        req.session.require2fa = false;
        req.flash('success', 'Two factor authentication is now disabled');
        res.redirect('/account/security');
    });
});

module.exports = router;

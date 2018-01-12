'use strict';

const config = require('wild-config');
const crypto = require('crypto');
const express = require('express');
const router = new express.Router();
const passport = require('../lib/passport');
const tools = require('../lib/tools');
const Joi = require('joi');
const apiClient = require('../lib/api-client');
const roleBasedAddresses = require('role-based-email-addresses');
const util = require('util');
const humanize = require('humanize');
const addressparser = require('addressparser');

// sub services
router.use('/filters', passport.checkLogin, require('./account/filters'));
router.use('/autoreply', passport.checkLogin, require('./account/autoreply'));

router.use('/security', passport.csrf, passport.checkLogin, require('./account/security'));

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

router.get('/logout', (req, res) => {
    req.session.require2fa = false;
    req.flash(); // clear pending messages
    passport.logout(req, res);
});

router.post('/login', (req, res, next) => passport.login(req, res, next));

router.get('/login', (req, res) => {
    res.render('account/login', {
        activeLogin: true
    });
});

router.get('/create', passport.csrf, (req, res, next) => {
    if (!config.service.allowJoin) {
        let err = new Error('User registration is disabled');
        err.status = 404;
        return next(err);
    }
    res.render('account/create', {
        title: 'Create new account',
        activeCreate: true,
        csrfToken: req.csrfToken()
    });
});

router.post('/create', passport.csrf, (req, res, next) => {
    if (!config.service.allowJoin) {
        let err = new Error('User registration is disabled');
        err.status = 404;
        return next(err);
    }
    const createSchema = {
        name: Joi.string()
            .trim()
            .min(3)
            .max(100)
            .label('Your name')
            .required(),
        address: Joi.string()
            .email()
            .trim()
            .max(255)
            .label('Your new address')
            .required(),
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

        language: Joi.string()
            .length(2)
            .default('en'),
        password2: Joi.string()
            .min(8)
            .max(100)
            .label('Password confirmation')
            .required(),
        username: Joi.string()
            .trim()
            .min(3)
            .max(128)
            .hostname()
            .lowercase()
            .label('Address')
            .required()
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

    let addressUser = result.value.address
        .split('@')
        .shift()
        .toLowerCase();
    if (
        ['abuse', 'admin', 'administrator', 'hostmaster', 'majordomo', 'postmaster', 'root', 'ssl-admin', 'webmaster'].includes(addressUser) ||
        roleBasedAddresses.includes(addressUser)
    ) {
        return showErrors({
            address: util.format('"%s" is a reserved username', addressUser)
        });
    }

    apiClient.users.create(
        {
            name: result.value.name,
            username: result.value.username,
            password: result.value.password,
            address: result.value.address,
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

router.get('/profile', passport.csrf, passport.checkLogin, (req, res, next) => {
    apiClient.users.get(req.user.id, (err, userData) => {
        if (err) {
            return next(err);
        }

        userData.forward = [].concat(userData.forward).join(', ');

        res.render('account/profile', {
            title: 'Account',
            activeProfile: true,
            values: userData,
            csrfToken: req.csrfToken()
        });
    });
});

router.post('/profile', passport.csrf, passport.checkLogin, (req, res) => {
    const updateSchema = Joi.object()
        .keys({
            name: Joi.string()
                .empty('')
                .max(100)
                .label('Your name'),

            forward: Joi.string()
                .empty('')
                .label('Forward address'),
            targetUrl: Joi.string()
                .trim()
                .uri({
                    scheme: ['http', 'https'],
                    allowRelative: false,
                    relativeOnly: false
                })
                .empty('')
                .label('Upload URL'),

            pubKey: Joi.string()
                .empty('')
                .trim()
                .regex(/^-----BEGIN PGP PUBLIC KEY BLOCK-----/, 'PGP key format'),
            encryptMessages: Joi.boolean()
                .truthy(['Y', 'true', 'yes', 'on', 1])
                .falsy(['N', 'false', 'no', 'off', 0, ''])
                .default(false),

            existingPassword: Joi.string()
                .empty('')
                .min(8)
                .max(100)
                .label('Current password'),
            password: Joi.string()
                .empty('')
                .min(8)
                .max(100)
                .label('New password')
                .valid(Joi.ref('password2'))
                .options({
                    language: {
                        any: {
                            allowOnly: '!!Passwords do not match'
                        }
                    }
                }),
            password2: Joi.string()
                .empty('')
                .min(8)
                .max(100)
                .label('Repeat password')
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

        if (Array.isArray(result.value.forward)) {
            result.value.forward = result.value.forward.join(', ');
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
    result.value.forward = addressparser(result.value.forward || '')
        .map(addr => tools.normalizeAddress(addr.address))
        .filter(fwd => fwd);

    result.value.targetUrl = result.value.targetUrl || '';
    result.value.pubKey = result.value.pubKey || '';

    result.value.sess = req.session.id;
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

router.post('/start-u2f', (req, res) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        return res.json({ error: err.message });
    }

    apiClient['2fa'].startU2f(req.user.id, req.ip, (err, data) => {
        if (err) {
            return res.json({ error: err.message });
        }
        res.json(data);
    });
});

router.post('/check-totp', passport.csrf, (req, res) => {
    const authSchema = Joi.object().keys({
        token: Joi.string()
            .length(6)
            .regex(/^[0-9]+$/, 'numbers')
            .required(),
        remember2fa: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, authSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    if (result.error) {
        return res.json({ error: result.error.message });
    }

    let remember2fa = result.value.remember2fa;
    apiClient['2fa'].checkTotp(req.user.id, result.value.token, req.session.id, req.ip, (err, result) => {
        if (err) {
            return res.json({ error: err.message, code: err.code });
        }

        if (!result) {
            return res.json({ error: 'Could not verify token' });
        }

        let data = {
            success: true,
            targetUrl: '/account/'
        };

        if (remember2fa) {
            data.remember2fa = {
                username: req.session.username,
                value: generate2faRemeberToken(req.user.id)
            };
        }

        req.session.require2fa = false;
        res.json(data);
    });
});

router.post('/check-u2f', passport.csrf, (req, res) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        return res.json({ error: err.message });
    }

    const authSchema = Joi.object().keys({
        keyHandle: Joi.string(),
        clientData: Joi.string(),
        signatureData: Joi.string(),
        errorCode: Joi.number(),
        errorMessage: Joi.string(),
        remember2fa: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, authSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    if (result.error) {
        return res.json({ error: result.error.message });
    }

    let requestData = { ip: req.ip };
    Object.keys(result.value || {}).forEach(key => {
        if (['signatureData', 'clientData', 'errorCode'].includes(key)) {
            requestData[key] = req.body[key];
        }
    });

    let remember2fa = result.value.remember2fa;

    requestData.ip = req.ip;
    requestData.sess = req.session.id;

    apiClient['2fa'].checkU2f(req.user.id, requestData, (err, data) => {
        if (err) {
            return res.json({ error: err.message });
        }

        if (!data || !data.success) {
            return res.json({ error: 'Could not verify key' });
        }

        if (remember2fa) {
            data.remember2fa = {
                username: req.session.username,
                value: generate2faRemeberToken(req.user.id)
            };
        }

        req.session.require2fa = false;
        data.targetUrl = '/account/';
        res.json(data);
    });
});

function generate2faRemeberToken(user) {
    let parts = [Date.now().toString(16), crypto.randomBytes(6).toString('hex')];

    let valueStr = parts.join('::');
    let hash = crypto
        .createHmac('sha256', config.totp.secret + ':' + user)
        .update(valueStr)
        .digest('hex');

    return valueStr + '::' + hash;
}

module.exports = router;

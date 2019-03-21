'use strict';

const config = require('wild-config');
const tokens = require('../lib/tokens');
const express = require('express');
const router = new express.Router();
const passport = require('../lib/passport');
const Joi = require('joi');
const apiClient = require('../lib/api-client');
const roleBasedAddresses = require('role-based-email-addresses');
const util = require('util');
const humanize = require('humanize');
const tools = require('../lib/tools');
const Recaptcha = require('express-recaptcha').Recaptcha;
let recaptcha;

let spamLevels = [
    { value: 0, description: 'Mark everything as spam' },
    { value: 25, description: 'Paranoid' },
    { value: 50, description: 'Normal' },
    { value: 75, description: 'Assume mostly ham' },
    { value: 100, description: 'Accept everything' }
];

if (config.recaptcha.enabled) {
    recaptcha = new Recaptcha(config.recaptcha.siteKey, config.recaptcha.secretKey);
}

const recaptchaVerify = function(req, res, next) {
    if (!config.recaptcha.enabled) {
        req.recaptcha = {
            error: false
        };
        return next();
    }
    recaptcha.middleware.verify(...arguments);
};

// sub services
router.use('/filters', passport.checkLogin, require('./account/filters'));
router.use('/autoreply', passport.checkLogin, require('./account/autoreply'));
router.use('/identities', passport.checkLogin, require('./account/identities'));

router.use('/security', passport.checkLogin, require('./account/security'));

router.get('/', passport.checkLogin, (req, res) => {
    res.render('account/index', {
        title: 'Overview',
        activeHome: true,
        accMenuOverview: true,

        address: req.user.address,

        quota: humanize.filesize(req.user.limits.quota.allowed),
        storageUsed: humanize.filesize(req.user.limits.quota.used),
        storageOverview: Math.round((req.user.limits.quota.used / req.user.limits.quota.allowed) * 100),

        recipients: humanize.numberFormat(req.user.limits.recipients.allowed, 0),
        recipientsSent: humanize.numberFormat(req.user.limits.recipients.used, 0),
        recipientsOverview: Math.round((req.user.limits.recipients.used / (req.user.limits.recipients.allowed || 1)) * 100),

        forwards: humanize.numberFormat(req.user.limits.forwards.allowed, 0),
        forwardsSent: humanize.numberFormat(req.user.limits.forwards.used, 0),
        forwardsOverview: Math.round((req.user.limits.forwards.used / (req.user.limits.forwards.allowed || 1)) * 100)
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
        activeLogin: true,
        csrfToken: req.csrfToken()
    });
});

router.get('/create', (req, res, next) => {
    if (!config.service.allowJoin) {
        let err = new Error('User registration is disabled');
        err.status = 404;
        return next(err);
    }

    let domain = config.service.domains.includes(config.service.domain) ? config.service.domain : config.service.domains[0];

    res.render('account/create', {
        title: 'Create new account',
        activeCreate: true,
        domains: config.service.domains,
        values: {
            domain
        },
        csrfToken: req.csrfToken()
    });
});

router.post('/create', recaptchaVerify, (req, res, next) => {
    if (!config.service.allowJoin) {
        let err = new Error('User registration is disabled');
        err.status = 404;
        return next(err);
    }
    const createSchema = {
        name: Joi.string()
            .trim()
            .min(1)
            .max(256)
            .label('Your name')
            .required(),
        domain: Joi.string()
            .trim()
            .valid(config.service.domains)
            .label('Domain')
            .required(),
        password: Joi.string()
            .min(8)
            .max(256)
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
            .max(256)
            .label('Password confirmation')
            .required(),
        username: Joi.string()
            .trim()
            .min(1)
            .max(128)
            .hostname()
            .lowercase()
            .label('Address')
            .required(),
        remember: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .valid(true),
        'g-recaptcha-response': Joi.string().strip()
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
            domains: config.service.domains,
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
        !config.service.enableSpecial &&
        (['abuse', 'admin', 'administrator', 'hostmaster', 'majordomo', 'postmaster', 'root', 'ssl-admin', 'webmaster'].includes(result.value.username) ||
            roleBasedAddresses.includes(result.value.username))
    ) {
        return showErrors({
            username: util.format('"%s" is a reserved username', result.value.username)
        });
    }

    let address = tools.normalizeAddress(result.value.username + '@' + result.value.domain);

    apiClient.users.create(
        {
            name: result.value.name,
            username: result.value.username,
            password: result.value.password,
            allowUnsafe: false,
            address,
            recipients: config.service.recipients,
            forwards: config.service.forwards,
            quota: config.service.quota * 1024 * 1024,
            sess: req.session.id,
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

            req.flash('success', 'Account created for ' + result.value.username + ' with address ' + address);
            res.redirect('/account/login/');
        }
    );
});

router.get('/profile', passport.checkLogin, (req, res) => {
    req.user.targets = []
        .concat(req.user.targets)
        .map(target => target.value)
        .join(', ');

    let defaultSpamLevel = typeof req.user.spamLevel === 'number' ? req.user.spamLevel : 50;

    res.render('account/profile', {
        title: 'Account',
        activeHome: true,
        accMenuProfile: true,

        spamLevels: spamLevels.map(level => ({
            value: level.value,
            description: level.description,
            selected: defaultSpamLevel === level.value
        })),

        values: req.user,
        csrfToken: req.csrfToken()
    });
});

router.post('/profile', passport.checkLogin, (req, res) => {
    const updateSchema = Joi.object()
        .keys({
            name: Joi.string()
                .empty('')
                .max(100)
                .label('Your name'),

            targets: Joi.array().items(
                Joi.string()
                    .trim()
                    .email()
                    .empty(''),
                Joi.string()
                    .trim()
                    .uri({
                        scheme: [/smtps?/, /https?/],
                        allowRelative: false,
                        relativeOnly: false
                    })
                    .empty('')
            ),

            pubKey: Joi.string()
                .empty('')
                .trim()
                .regex(/^-----BEGIN PGP PUBLIC KEY BLOCK-----/, 'PGP key format'),
            encryptMessages: Joi.boolean()
                .truthy(['Y', 'true', 'yes', 'on', 1])
                .falsy(['N', 'false', 'no', 'off', 0, ''])
                .default(false),

            spamLevel: Joi.number()
                .empty('')
                .min(0)
                .max(100),

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

    if (typeof req.body.targets === 'string' && req.body.targets) {
        req.body.targets = req.body.targets.split(',');
    } else {
        req.body.targets = [];
    }

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

        if (Array.isArray(result.value.targets)) {
            result.value.targets = result.value.targets.join(', ');
        }

        res.render('account/profile', {
            title: 'Account',
            activeHome: true,
            accMenuProfile: true,

            spamLevels: spamLevels.map(level => ({
                value: level.value,
                description: level.description,
                selected: result.value.spamLevel === level.value
            })),

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
    result.value.targets = result.value.targets || '';
    result.value.pubKey = result.value.pubKey || '';

    result.value.sess = req.session.id;
    result.value.ip = req.ip;

    result.value.allowUnsafe = false;
    apiClient.users.update(req.user, result.value, err => {
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
        return res.json({ error: err.message, code: err.code });
    }

    apiClient['2fa'].startU2f(req.user, req.ip, (err, data) => {
        if (err) {
            return res.json({ error: err.message, code: err.code });
        }
        res.json(data);
    });
});

router.post('/check-totp', (req, res) => {
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
    apiClient['2fa'].checkTotp(req.user, result.value.token, req.session.id, req.ip, (err, result) => {
        if (err) {
            return res.json({ error: err.message, code: err.code });
        }

        if (!result) {
            return res.json({ error: 'Could not verify token' });
        }

        let data = {
            success: true,
            targetUrl: '/webmail/'
        };

        if (remember2fa) {
            data.remember2fa = {
                username: req.session.username,
                value: tokens.generateToken(req.user.id, tokens.TOKEN_2FA),
                days: tokens.DAYS_2FA
            };
        }

        data.successlog = {
            username: req.session.username,
            value: tokens.generateToken(req.user.id, tokens.TOKEN_RECOVERY),
            days: tokens.DAYS_RECOVERY
        };

        req.session.require2fa = false;
        res.json(data);
    });
});

router.post('/check-u2f', (req, res) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        return res.json({ error: err.message, code: err.code });
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

    apiClient['2fa'].checkU2f(req.user, requestData, (err, data) => {
        if (err) {
            return res.json({ error: err.message, code: err.code });
        }

        if (!data || !data.success) {
            return res.json({ error: 'Could not verify key' });
        }

        if (remember2fa) {
            data.remember2fa = {
                username: req.session.username,
                value: tokens.generateToken(req.user.id, tokens.TOKEN_2FA),
                days: tokens.DAYS_2FA
            };
        }

        data.successlog = {
            username: req.session.username,
            value: tokens.generateToken(req.user.id, tokens.TOKEN_RECOVERY),
            days: tokens.DAYS_RECOVERY
        };

        req.session.require2fa = false;
        data.targetUrl = '/webmail/';
        res.json(data);
    });
});

router.post('/update-password', (req, res) => {
    if (!req.session.requirePasswordChange) {
        // only allow changing password if requirePasswordChange flag is set

        if (req.user) {
            req.flash('warning', 'Password is already updated');
            res.redirect('/account/security/password');
        } else {
            req.flash('danger', 'Need to be logged in to change password');
            res.redirect('/account/login');
        }
        return;
    }

    const updateSchema = Joi.object().keys({
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
            })
            .required(),
        password2: Joi.string()
            .empty('')
            .min(8)
            .max(100)
            .label('Repeat password')
            .required()
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Password update failed');
        }

        res.render('account/update-password', {
            layout: 'layout-popup',
            title: 'Change password',

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
                if (!errors[path]) {
                    errors[path] = detail.message;
                }
            });
        }
        return showErrors(errors);
    }

    delete result.value.password2;

    // disable 2fa when password reset is used
    result.value.disable2fa = true;

    result.value.sess = req.session.id;
    result.value.ip = req.ip;

    result.value.allowUnsafe = false;
    apiClient.users.update(req.user, result.value, err => {
        if (err) {
            if (err.fields) {
                return showErrors(err.fields);
            } else {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }
        }

        req.session.requirePasswordChange = false;
        req.flash('success', 'Account password updated');
        res.redirect('/webmail');
    });
});

module.exports = router;

'use strict';

const config = require('wild-config');
const express = require('express');
const router = new express.Router();
const Joi = require('joi');
const apiClient = require('../../lib/api-client');

const AUTH_EVENTS = new Map([
    ['create asp', 'Create new Application Specific Password'],
    ['delete asp', 'Deleted Application Specific Password'],
    ['account created', 'Account was created'],
    ['enable 2fa totp', 'Enable 2FA mobile authenticator'],
    ['disable 2fa totp', 'Disable 2FA mobile authenticator'],
    ['check 2fa totp', 'Authenticating with mobile authenticator'],
    ['enable 2fa u2f', 'Enable 2FA security key'],
    ['disable 2fa u2f', 'Disable 2FA security key'],
    ['check 2fa u2f', 'Authenticating with security key'],
    ['disable 2fa', 'Disable 2FA on account'],
    ['password change', 'Changing account password'],
    ['authentication', 'Authenticating with password']
]);

router.get('/', (req, res) => {
    res.render('account/security/2fa', {
        title: 'Security',
        activeSecurity: true,
        secMenu2fa: true,

        values: req.user,
        enabled2fa: req.user.enabled2fa,
        enabledTotp: req.user.enabled2fa ? req.user.enabled2fa.includes('totp') : false,
        enabledU2f: req.user.enabled2fa ? req.user.enabled2fa.includes('u2f') : false,

        csrfToken: req.csrfToken()
    });
});

router.get('/events', (req, res, next) => {
    const updateSchema = Joi.object().keys({
        event: Joi.string()
            .empty('')
            .trim()
            .hex()
            .length(24)
            .label('Password ID'),
        next: Joi.string()
            .max(100)
            .empty(''),
        previous: Joi.string()
            .max(100)
            .empty(''),
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
        return res.redirect('/account/security/events');
    }

    let getEvents = done => {
        if (result.value.event) {
            return apiClient.authlog.get(req.user, result.value.event, (err, eventData) => {
                if (err) {
                    return done(err);
                }
                done(null, {
                    page: 0,
                    results: [].concat(eventData || [])
                });
            });
        }

        apiClient.authlog.list(req.user, { next: result.value.next, previous: result.value.previous, page: result.value.page || 1 }, done);
    };

    getEvents((err, log) => {
        if (err) {
            return next(err);
        }
        log.title = 'Security';
        log.activeSecurity = true;
        log.secMenuEvents = true;
        log.nextPage = log.page + 1;
        log.previousPage = Math.max(log.page - 1, 1);
        log.results.forEach(entry => {
            if (entry.asp) {
                entry.asp = {
                    id: entry.asp,
                    name: (entry.aname || '').toString()
                };

                if (entry.asp.name.length > 12) {
                    entry.asp.name = entry.asp.name.substr(0, 12) + '…';
                }
            }
            if (!entry.protocol || entry.protocol === 'API') {
                entry.protocol = 'Web';
            }
            entry.ip = entry.ip ? entry.ip.replace(/^::ffff:/i, '') : false;
            entry.action = AUTH_EVENTS.get(entry.action) || entry.action;
            switch (entry.result) {
                case 'success':
                    entry.label = 'success';
                    entry.result = 'Success';
                    break;
                case 'fail':
                    entry.label = 'danger';
                    entry.result = 'Failed';
                    break;
            }

            entry.sessStr = entry.sess ? (entry.sess || '').toString() : false;
            if (entry.sessStr && entry.sessStr.length > 12) {
                entry.sessStr = entry.sessStr.substr(0, 12) + '…';
            }
        });
        res.render('account/security/events', log);
    });
});

router.get('/gpg', (req, res) => {
    res.render('account/security/gpg', {
        title: 'Security',
        activeSecurity: true,
        secMenuGpg: true,

        values: req.user,
        fingerprint: req.user.keyInfo ? formatFingerprint(req.user.keyInfo.fingerprint) : false,
        keyAddress: req.user.keyInfo ? req.user.keyInfo.address : false,

        csrfToken: req.csrfToken()
    });
});

router.post('/gpg', (req, res) => {
    const updateSchema = Joi.object().keys({
        removeKey: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false),
        pubKey: Joi.string()
            .empty('')
            .trim()
            .regex(/^-----BEGIN PGP PUBLIC KEY BLOCK-----/, 'PGP key format'),
        encryptMessages: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Account update failed');
        }

        if (Array.isArray(result.value.forward)) {
            result.value.forward = result.value.forward.join(', ');
        }

        res.render('account/security/gpg', {
            title: 'Security',
            activeSecurity: true,
            secMenuGpg: true,

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

    if (!req.user.address) {
        return res.redirect('/account/security');
    }

    let updatedUserData = {
        encryptMessages: result.value.encryptMessages,
        ip: req.ip,
        sess: req.session.id
    };

    if (result.value.pubKey) {
        updatedUserData.pubKey = result.value.pubKey;
    }

    if (result.value.removeKey) {
        updatedUserData.pubKey = updatedUserData.pubKey || '';
        if (!updatedUserData.pubKey) {
            updatedUserData.encryptMessages = false;
        }
    }

    if (!req.user.keyInfo && !updatedUserData.pubKey && updatedUserData.encryptMessages) {
        updatedUserData.encryptMessages = false;
        updatedUserData.encryptForwarded = false;
    }

    updatedUserData.allowUnsafe = false;
    apiClient.users.update(req.user, updatedUserData, err => {
        if (err) {
            if (err.fields) {
                return showErrors(err.fields);
            } else {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }
        }

        req.flash('success', 'Updated encryption settings');
        res.redirect('/account/security/gpg');
    });
});

router.get('/password', (req, res) => {
    res.render('account/security/password', {
        title: 'Security',
        activeSecurity: true,
        secMenuPassword: true,

        values: req.user,

        csrfToken: req.csrfToken()
    });
});

router.post('/password', (req, res) => {
    const updateSchema = Joi.object().keys({
        existingPassword: Joi.string()
            .empty('')
            .min(8)
            .max(100)
            .label('Current password')
            .required(),
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

        if (Array.isArray(result.value.forward)) {
            result.value.forward = result.value.forward.join(', ');
        }

        res.render('account/security/password', {
            title: 'Account',
            activeProfile: true,
            secMenuPassword: true,
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

    result.value.ip = req.ip;
    result.value.sess = req.session.id;

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

        req.flash('success', 'Account password updated');
        res.redirect('/account/security/password');
    });
});

router.get('/asps', (req, res) => {
    apiClient.asps.list(req.user, (err, asps) => {
        if (err) {
            req.flash('danger', 'Account password updated');
            res.redirect('/account/security');
        }
        res.render('account/security/asps', {
            title: 'Security',
            activeSecurity: true,
            secMenuAsps: true,

            values: req.user,

            csrfToken: req.csrfToken(),

            asps: asps.reverse().map((entry, i) => {
                entry.index = i + 1;

                entry.scope = entry.scopes.includes('*') ? 'All' : entry.scopes.join(', ');
                return entry;
            })
        });
    });
});

router.post('/asps/delete', (req, res) => {
    const updateSchema = Joi.object().keys({
        id: Joi.string()
            .trim()
            .hex()
            .length(24)
            .label('Password ID')
            .required()
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
        return res.redirect('/account/security/asps');
    }

    apiClient.asps.del(req.user, result.value.id, req.session.id, req.ip, err => {
        if (err) {
            req.flash('danger', 'Database Error, failed to delete data');
            return res.redirect('/account/security/asps');
        }

        req.flash('success', 'Application specific password was deleted');
        return res.redirect('/account/security/asps');
    });
});

router.post('/asps/create', (req, res) => {
    const updateSchema = Joi.object().keys({
        description: Joi.string()
            .trim()
            .min(0)
            .max(256)
            .label('Description')
            .required()
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
        ip: req.ip,
        sess: req.session.id
    };

    apiClient.asps.create(req.user, data, (err, response) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/security');
        }

        res.render('account/security/asp', {
            layout: 'layout-popup',
            description: result.value.description,
            password: response.password,
            mobileconfig: response.mobileconfig,
            csrfToken: req.csrfToken(),
            passwordFormatted: response.password.replace(/.{4}/g, '$& ').trim()
        });
    });
});

router.get('/2fa', (req, res) => {
    res.render('account/security/2fa', {
        title: 'Security',
        activeSecurity: true,
        secMenu2fa: true,

        values: req.user,
        enabled2fa: req.user.enabled2fa,
        enabledTotp: req.user.enabled2fa ? req.user.enabled2fa.includes('totp') : false,
        enabledU2f: req.user.enabled2fa ? req.user.enabled2fa.includes('u2f') : false,

        csrfToken: req.csrfToken()
    });
});

router.post('/2fa/enable-totp', (req, res, next) => {
    const authSchema = Joi.object().keys({
        token: Joi.string()
            .length(6)
            .regex(/^[0-9]+$/, 'numbers')
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, authSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = errors => {
        apiClient['2fa'].setupTotp(req.user, config.totp.issuer || config.name, req.ip, (err, data) => {
            if (err) {
                return next(err);
            }
            res.render('account/security/enable-totp', {
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

    apiClient['2fa'].setupTotp(req.user, config.totp.issuer || config.name, req.ip, (err, data) => {
        if (err) {
            return next(err);
        }
        res.render('account/security/enable-totp', {
            layout: 'layout-popup',
            title: 'Two factor authentication',
            activeSecurity: true,
            csrfToken: req.csrfToken(),
            imageUrl: data.qrcode
        });
    });
});

router.post('/2fa/verify-totp', (req, res) => {
    const authSchema = Joi.object().keys({
        token: Joi.string()
            .length(6)
            .regex(/^[0-9]+$/, 'numbers')
            .required()
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

    apiClient['2fa'].verifyTotp(req.user, result.value.token, req.session.id, req.ip, err => {
        if (err) {
            return res.json({ error: err.message, code: err.code });
        }

        req.flash('success', 'Two factor authentication is now enabled');
        res.json({
            success: true,
            targetUrl: '/account/security/2fa'
        });
    });
});

router.post('/2fa/disable-totp', (req, res, next) => {
    apiClient['2fa'].disable(req.user, req.session.id, req.ip, err => {
        if (err) {
            return next(err);
        }
        req.session.require2fa = false;
        req.flash('success', 'Two factor authentication is now disabled');
        res.redirect('/account/security/2fa');
    });
});

router.post('/2fa/enable-u2f', (req, res, next) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        err.status = 404;
        return next(err);
    }

    res.render('account/security/enable-u2f', {
        layout: 'layout-popup',
        title: 'Two factor authentication',
        activeSecurity: true,
        csrfToken: req.csrfToken()
    });
});

router.post('/2fa/setup-u2f', (req, res) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        return res.json({ error: err.message });
    }

    apiClient['2fa'].setupU2f(req.user, req.ip, (err, data) => {
        if (err) {
            return res.json({ error: err.message });
        }
        req.flash('success', 'U2F key was added to your account');
        res.json(data);
    });
});

router.post('/2fa/disable-u2f', (req, res, next) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        err.status = 404;
        return next(err);
    }

    apiClient['2fa'].disableU2f(req.user, req.session.id, req.ip, (err, data) => {
        if (err) {
            return next(err);
        }
        if (!data.success) {
            return next(new Error('Did not receive U2F data'));
        }
        req.flash('success', 'U2F was disabled');
        res.redirect('/account/security/2fa');
    });
});

router.post('/2fa/enable-u2f/verify', (req, res) => {
    if (!config.u2f.enabled) {
        let err = new Error('U2F support is disabled');
        return res.json({ error: err.message });
    }

    let requestData = { sess: req.session.id, ip: req.ip };
    Object.keys(req.body || {}).forEach(key => {
        if (['registrationData', 'clientData', 'errorCode'].includes(key)) {
            requestData[key] = req.body[key];
        }
    });
    apiClient['2fa'].enableU2f(req.user, requestData, (err, data) => {
        if (err) {
            return res.json({ error: err.message });
        }
        data.targetUrl = '/account/security/2fa';
        res.json(data);
    });
});

function formatFingerprint(fingerprint) {
    return ((fingerprint || '').toString().match(/(.{1,2})/g) || []).join(':');
}

module.exports = router;

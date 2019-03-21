'use strict';

const config = require('wild-config');
const express = require('express');
const router = new express.Router();
const apiClient = require('../../lib/api-client');
const Joi = require('joi');
const roleBasedAddresses = require('role-based-email-addresses');
const util = require('util');

router.get('/', (req, res, next) => {
    apiClient.addresses.list(req.user, (err, identities) => {
        if (err) {
            return next(err);
        }

        res.render('account/identities', {
            title: 'Identities',
            activeHome: true,
            accMenuIdentities: true,

            canCreate: identities.length < config.service.identities,
            canEdit: config.service.allowIdentityEdit,
            identities: identities.map((identity, i) => {
                identity.index = i + 1;
                return identity;
            }),
            csrfToken: req.csrfToken()
        });
    });
});

router.get('/create', (req, res) => {
    apiClient.addresses.list(req.user, (err, identities) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/identities');
        }

        if (identities && identities.length >= config.service.identities) {
            req.flash('danger', 'Maximum amount of identities created');
            return res.redirect('/account/identities');
        }

        let domain = config.service.domains.includes(config.service.domain) ? config.service.domain : config.service.domains[0];

        res.render('account/identities/create', {
            title: 'Add address',
            activeHome: true,
            accMenuIdentities: true,

            domains: config.service.domains,
            values: {
                domain
            },
            csrfToken: req.csrfToken()
        });
    });
});

router.post('/create', (req, res) => {
    const createSchema = {
        name: Joi.string()
            .empty('')
            .trim()
            .max(128)
            .label('Identity name'),
        address: Joi.string()
            .trim()
            .min(1)
            .max(128)
            .lowercase()
            .regex(/^[a-zA-Z0-9.\-\u0080-\uFFFF]+$/, 'address')
            .label('Address')
            .required(),
        domain: Joi.string()
            .trim()
            .valid(config.service.domains)
            .label('Domain')
            .required(),
        main: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    };

    delete req.body._csrf;
    let result = Joi.validate(req.body, createSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Failed to create address');
        }

        res.render('account/identities/create', {
            title: 'Add address',
            activeHome: true,
            accMenuIdentities: true,

            domains: config.service.domains,
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

    if (
        !config.service.enableSpecial &&
        (['abuse', 'admin', 'administrator', 'hostmaster', 'majordomo', 'postmaster', 'root', 'ssl-admin', 'webmaster'].includes(result.value.address) ||
            roleBasedAddresses.includes(result.value.address))
    ) {
        return showErrors({
            address: util.format('"%s" is a reserved username', result.value.address)
        });
    }

    apiClient.addresses.list(req.user, (err, identities) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/identities');
        }

        if (identities && identities.length >= config.service.identities) {
            req.flash('danger', 'Maximum amount of identities created');
            return res.redirect('/account/identities');
        }

        apiClient.addresses.create(
            req.user,
            {
                name: result.value.name,
                address: result.value.address + '@' + result.value.domain,
                main: result.value.main
            },
            (err, data) => {
                if (err) {
                    req.flash('danger', err.message);
                    return showErrors(false, true);
                }
                req.flash('success', 'Address was created');
                return res.redirect('/account/identities?created=' + encodeURIComponent(data.id));
            }
        );
    });
});

router.get('/edit', (req, res) => {
    if (!config.service.allowIdentityEdit) {
        req.flash('danger', "You're not allowed to edit an identity");
        return res.redirect('/account/identities');
    }

    const updateSchema = Joi.object().keys({
        id: Joi.string()
            .trim()
            .hex()
            .length(24)
            .label('Identity ID')
            .required()
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
        return res.redirect('/account/identities');
    }

    apiClient.addresses.get(req.user, result.value.id, (err, address) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/identities');
        }
        address.domain = address.address.substr(address.address.indexOf('@') + 1);
        address.address = address.address.substr(0, address.address.indexOf('@'));

        res.render('account/identities/edit', {
            title: 'Edit address',
            activeHome: true,
            accMenuIdentities: true,

            domains: config.service.domains,
            values: address,
            isMain: address.main,

            csrfToken: req.csrfToken()
        });
    });
});

router.post('/edit', (req, res) => {
    if (!config.service.allowIdentityEdit) {
        req.flash('danger', "You're not allowed to edit an identity");
        return res.redirect('/account/identities');
    }

    const createSchema = {
        id: Joi.string()
            .trim()
            .hex()
            .length(24)
            .label('Filtri ID')
            .required(),
        name: Joi.string()
            .empty('')
            .trim()
            .max(128)
            .label('Identity name'),
        address: Joi.string()
            .trim()
            .min(1)
            .max(128)
            .lowercase()
            .regex(/^[a-zA-Z0-9.\-\u0080-\uFFFF]+$/, 'address')
            .label('Address')
            .required(),
        domain: Joi.string()
            .trim()
            .valid(config.service.domains)
            .label('Domain')
            .required(),
        main: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    };

    delete req.body._csrf;
    let result = Joi.validate(req.body, createSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    apiClient.addresses.get(req.user, result.value.id, (err, address) => {
        if (err) {
            req.flash('danger', err.message);
            return res.redirect('/account/identities');
        }

        let showErrors = (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to update identity');
            }

            res.render('account/identities/edit', {
                title: 'Edit address',
                activeHome: true,
                accMenuIdentities: true,

                domains: config.service.domains,
                values: result.value,
                isMain: address.main,

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

        // allow keeping existing priority usernames, disallow adding additional
        if (address.address.substr(0, address.address.indexOf('@')) !== result.value.address) {
            if (
                ['abuse', 'admin', 'administrator', 'hostmaster', 'majordomo', 'postmaster', 'root', 'ssl-admin', 'webmaster'].includes(result.value.address) ||
                roleBasedAddresses.includes(result.value.address)
            ) {
                return showErrors({
                    address: util.format('"%s" is a reserved username', result.value.address)
                });
            }
        }

        let updateData = {
            name: result.value.name,
            address: result.value.address + '@' + result.value.domain
        };

        if (result.value.main) {
            // do not send by default, only if it is true
            updateData.main = result.value.main;
        }

        apiClient.addresses.update(req.user, result.value.id, updateData, err => {
            if (err) {
                req.flash('danger', err.message);
                return showErrors(false, true);
            }
            req.flash('success', 'Identity was updated');
            return res.redirect('/account/identities?updated=' + encodeURIComponent(result.value.id));
        });
    });
});

router.post('/delete', (req, res) => {
    const updateSchema = Joi.object().keys({
        id: Joi.string()
            .trim()
            .hex()
            .length(24)
            .label('Identity ID')
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
        return res.redirect('/account/identities');
    }

    apiClient.addresses.del(req.user, result.value.id, err => {
        if (err) {
            req.flash('danger', 'Database Error, failed to update user and delete identity');
            return res.redirect('/account/identities');
        }

        req.flash('success', 'User data updated, identity was deleted');
        return res.redirect('/account/identities');
    });
});

module.exports = router;

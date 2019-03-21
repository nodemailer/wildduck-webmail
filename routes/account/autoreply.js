'use strict';

const express = require('express');
const router = new express.Router();
const Joi = require('joi');
const apiClient = require('../../lib/api-client');

router.get('/', (req, res, next) => {
    apiClient.autoreply.get(req.user, (err, autoreply) => {
        if (err) {
            return next(err);
        }
        res.render('account/autoreply', {
            title: 'Autoreply',
            activeAutoreply: true,
            values: autoreply,
            csrfToken: req.csrfToken()
        });
    });
});

router.post('/', (req, res) => {
    const updateSchema = Joi.object().keys({
        status: Joi.boolean().required(),
        name: Joi.string()
            .empty('')
            .trim()
            .max(128),
        subject: Joi.string()
            .empty('')
            .trim()
            .max(128),
        text: Joi.string()
            .empty('')
            .trim()
            .max(10 * 1024),
        start: Joi.date().empty(''),
        end: Joi.date()
            .empty('')
            .min(Joi.ref('start'))
    });

    delete req.body._csrf;
    let result = Joi.validate(req.body, updateSchema, {
        abortEarly: false,
        convert: true,
        allowUnknown: false
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Update failed');
        }

        res.render('account/autoreply', {
            title: 'Autoreply',
            activeAutoreply: true,
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

    if (!result.value.name && 'name' in req.body) {
        result.value.name = '';
    }

    if (!result.value.subject && 'subject' in req.body) {
        result.value.subject = '';
    }

    if (!result.value.text && 'text' in req.body) {
        result.value.text = '';
    }

    apiClient.autoreply.update(req.user, result.value, err => {
        if (err) {
            if (err.fields) {
                return showErrors(err.fields);
            } else {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }
        }

        req.flash('success', 'Autoreply is updated');
        res.redirect('/account/autoreply/');
    });
});

module.exports = router;

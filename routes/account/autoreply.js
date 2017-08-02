'use strict';

const express = require('express');
const router = new express.Router();
const passport = require('../../lib/passport');
const Joi = require('joi');
const apiClient = require('../../lib/api-client');

router.get('/', passport.csrf, (req, res, next) => {
    apiClient.autoreply.get(req.user.id, (err, autoreply) => {
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

router.post('/', passport.parse, passport.csrf, (req, res) => {
    const updateSchema = Joi.object().keys({
        status: Joi.boolean().required(),
        subject: Joi.string().empty('').trim().max(128),
        message: Joi.string().empty('').trim().max(10 * 1024)
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

    if (!result.value.subject && 'subject' in req.body) {
        result.value.subject = '';
    }

    if (!result.value.message && 'message' in req.body) {
        result.value.message = '';
    }

    apiClient.autoreply.update(req.user.id, result.value, err => {
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

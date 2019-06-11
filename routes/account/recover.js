'use strict';

const express = require('express');
const router = new express.Router();
const Joi = require('joi');
const apiClient = require('../../lib/api-client');

router.get('/', (req, res) => {
    res.render('account/recover', {
        title: 'Recover messages',
        activeHome: true,
        accMenuRecover: true,
        values: {},
        csrfToken: req.csrfToken()
    });
});

router.post('/', (req, res) => {
    const updateSchema = Joi.object().keys({
        start: Joi.date()
            .empty('')
            .required(),
        end: Joi.date()
            .empty('')
            .min(Joi.ref('start'))
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
            req.flash('danger', 'Message recovery failed');
        }

        res.render('account/recover', {
            title: 'Recover messages',
            activeHome: true,
            accMenuRecover: true,
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

    apiClient.recover.create(
        req.user,
        {
            start: result.value.start.toISOString(),
            end: result.value.end.toISOString(),
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

            req.flash('success', 'Recovery was initiated');
            res.redirect('/account/recover');
        }
    );
});

module.exports = router;

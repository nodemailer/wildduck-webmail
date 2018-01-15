'use strict';

const Joi = require('joi');
const apiClient = require('../lib/api-client');
const express = require('express');
const router = new express.Router();

/* GET home page. */
router.post('/toggle/flagged', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$|^\d+:\d+$|/i)
            .required(),
        flagged: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
    });

    delete req.body._csrf;

    let result = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        return res.json({
            error: result.error.message
        });
    }

    apiClient.messages.update(
        req.user.id,
        result.value.mailbox,
        result.value.message,
        {
            flagged: result.value.flagged
        },
        (err, response) => {
            if (err) {
                return res.json(err.message);
            }
            res.json(response);
        }
    );
});

/* GET home page. */
router.post('/toggle/seen', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$|^\d+:\d+$|/i)
            .required(),
        seen: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
    });

    delete req.body._csrf;

    let result = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        return res.json({
            error: result.error.message
        });
    }

    apiClient.messages.update(
        req.user.id,
        result.value.mailbox,
        result.value.message,
        {
            seen: result.value.seen
        },
        (err, response) => {
            if (err) {
                return res.json(err.message);
            }
            res.json(response);
        }
    );
});

module.exports = router;

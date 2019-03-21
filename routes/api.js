'use strict';

const Joi = require('joi');
const apiClient = require('../lib/api-client');
const express = require('express');
const router = new express.Router();
const tools = require('../lib/tools');

router.post('/toggle/flagged', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$/i)
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
        req.user,
        result.value.mailbox,
        {
            message: result.value.message,
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

router.post('/toggle/seen', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$/i)
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
        req.user,
        result.value.mailbox,
        {
            message: result.value.message,
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

router.post('/move', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$/i)
            .required(),
        target: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required()
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
        req.user,
        result.value.mailbox,
        {
            message: result.value.message,
            moveTo: result.value.target
        },
        (err, response) => {
            if (err) {
                return res.json(err.message);
            }
            res.json(response);
        }
    );
});

router.post('/delete', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.string()
            .regex(/^\d+(,\d+)*$/i)
            .required()
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

    apiClient.mailboxes.list(req.user, true, (err, mailboxes) => {
        if (err) {
            return res.json({ error: err.message });
        }

        let mailbox = mailboxes.find(box => box.id === result.value.mailbox);
        let trash = mailboxes.find(box => box.specialUse === '\\Trash');
        if (!mailbox) {
            return res.json({
                error: 'Invalid mailbox'
            });
        }

        if (mailbox.specialUse === '\\Trash' || mailbox.specialUse === '\\Junk' || !trash) {
            // delete permanently

            let messages = result.value.message
                .split(',')
                .map(id => Number(id))
                .filter(id => id);
            let pos = 0;
            let deleted = [];
            let processNext = () => {
                if (pos >= messages.length) {
                    return res.json({
                        success: true,
                        action: 'delete',
                        id: deleted
                    });
                }
                let id = messages[pos++];

                apiClient.messages.delete(req.user, result.value.mailbox, id, (err, response) => {
                    if (err) {
                        deleted.push([id, false, { error: err.message, code: err.code }]);
                    } else {
                        deleted.push([id, (response && response.success) || false]);
                    }
                    setImmediate(processNext);
                });
            };
            return setImmediate(processNext);
        } else {
            // move to trash
            apiClient.messages.update(
                req.user,
                result.value.mailbox,
                {
                    message: result.value.message,
                    moveTo: trash.id
                },
                (err, response) => {
                    if (err) {
                        return res.json(err.message);
                    }
                    response.action = 'move';
                    res.json(response);
                }
            );
        }
    });
});

router.post('/list', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .allow('starred')
            .required(),
        cursorType: Joi.string()
            .empty('')
            .valid('next', 'previous'),
        cursorValue: Joi.string()
            .max(100)
            .empty(''),
        page: Joi.number()
            .empty('')
            .default(1)
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

    let params = {};
    if (result.value.cursorType && result.value.cursorValue) {
        params[result.value.cursorType] = result.value.cursorValue;
    }

    let makeRequest = done => {
        if (result.value.mailbox === 'starred') {
            params.flagged = true;
            params.searchable = true;
            return apiClient.messages.search(req.user, params, done);
        } else {
            apiClient.messages.list(req.user, result.value.mailbox, params, done);
        }
    };

    makeRequest((err, response) => {
        if (err) {
            return res.json(err.message);
        }
        response.results.forEach(message => {
            message.fromHtml = tools.getAddressesHTML(message.from, true);
        });
        res.json(response);
    });
});

router.get('/events', (req, res) => {
    apiClient.updates.stream(req, res, req.user);
});

router.post('/upload', (req, res) =>
    res.json({
        file: req.file,
        initialPreview: ["<img src='/images/desert.jpg' class='file-preview-image' alt='Desert' title='Desert'>"],
        initialPreviewConfig: [
            {
                caption: 'desert.jpg',
                url: '/api/deleteUpload',
                key: Date.now(),
                extra: {
                    id: 102
                }
            }
        ]
    })
);

module.exports = router;

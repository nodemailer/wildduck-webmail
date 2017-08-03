'use strict';

const express = require('express');
const router = new express.Router();
const apiClient = require('../lib/api-client');
const Joi = require('joi');
const tools = require('../lib/tools');

/* GET home page. */
router.get('/', renderMailbox);
router.get('/:mailbox', renderMailbox);

router.get('/:mailbox/message/:message', (req, res, next) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string().hex().length(24),
        message: Joi.number().min(1)
    });

    let result = Joi.validate(req.params, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/webmail');
    }

    apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
        if (err) {
            return next(err);
        }

        let mailbox = result.value.mailbox || mailboxes[0].id;
        let mailboxExists = false;
        let selectedMailbox = false;
        mailboxes.forEach((entry, i) => {
            entry.index = i + 1;
            if (entry.id === mailbox) {
                entry.selected = true;
                mailboxExists = true;
                selectedMailbox = entry;
            }
        });

        if (!mailboxExists) {
            return res.redirect('/webmail');
        }

        apiClient.messages.get(req.user.id, mailbox, result.value.message, (err, messageData) => {
            if (err) {
                return next(err);
            }

            if (!messageData) {
                return res.redirect('/webmail');
            }

            let info = [];

            info.push({
                key: 'From',
                isHtml: true,
                value: tools.getAddressesHTML(
                    messageData.from ||
                    messageData.sender || {
                        name: '< >'
                    }
                )
            });

            if (messageData.to) {
                info.push({
                    key: 'To',
                    isHtml: true,
                    value: tools.getAddressesHTML(messageData.to)
                });
            }

            if (messageData.cc) {
                info.push({
                    key: 'Cc',
                    isHtml: true,
                    value: tools.getAddressesHTML(messageData.cc)
                });
            }

            if (messageData.bcc) {
                info.push({
                    key: 'Bcc',
                    isHtml: true,
                    value: tools.getAddressesHTML(messageData.bcc)
                });
            }

            if (messageData.replyTo) {
                info.push({
                    key: 'Reply To',
                    isHtml: true,
                    value: tools.getAddressesHTML(messageData.replyTo)
                });
            }

            info.push({
                key: 'Time',
                isDate: true,
                value: messageData.date
            });

            messageData.html = (messageData.html || [])
                .map(html =>
                    html.replace(/attachment:([a-f0-9]+)\/(ATT\d+)/g, (str, mid, aid) => '/webmail/' + mailbox + '/attachment/' + messageData.id + '/' + aid)
                );

            messageData.info = info;
            res.render('webmail/message', {
                activeWebmail: true,
                mailboxes,
                mailbox: selectedMailbox,
                message: messageData,
                messageJson: JSON.stringify(messageData).replace(/\//g, '\\u002f')
            });
        });
    });
});

router.get('/:mailbox/attachment/:message/:attachment', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string().hex().lowercase().length(24).required(),
        message: Joi.number().min(1).required(),
        attachment: Joi.string().regex(/^ATT\d+$/i).uppercase().required()
    });

    let result = Joi.validate(req.params, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/webmail');
    }

    apiClient.attachment.get(req, res, req.user.id, result.value.mailbox, result.value.message, result.value.attachment);
});

router.get('/:mailbox/raw/:message.eml', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string().hex().lowercase().length(24).required(),
        message: Joi.number().min(1).required()
    });

    let result = Joi.validate(req.params, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/webmail');
    }

    apiClient.messages.raw(req, res, req.user.id, result.value.mailbox, result.value.message);
});

function renderMailbox(req, res, next) {
    const schema = Joi.object().keys({
        mailbox: Joi.string().hex().length(24).empty(''),
        next: Joi.string().max(100).empty(''),
        previous: Joi.string().max(100).empty(''),
        page: Joi.number().empty('')
    });

    if (req.params.mailbox) {
        req.query.mailbox = req.params.mailbox;
    }

    let result = Joi.validate(req.query, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    if (result.error) {
        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                req.flash('danger', detail.message);
            });
        }
        return res.redirect('/webmail');
    }

    apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
        if (err) {
            return next(err);
        }

        let mailbox = result.value.mailbox || mailboxes[0].id;
        let mailboxExists = false;
        let selectedMailbox = false;
        mailboxes.forEach((entry, i) => {
            entry.index = i + 1;
            if (entry.id === mailbox) {
                entry.selected = true;
                mailboxExists = true;
                selectedMailbox = entry;
            }
        });

        if (!mailboxExists) {
            return res.redirect('/webmail');
        }

        apiClient.messages.list(req.user.id, mailbox, { next: req.query.next, previous: req.query.previous, page: result.value.page || 1 }, (err, result) => {
            if (err) {
                return next(err);
            }

            res.render('webmail/index', {
                activeWebmail: true,
                mailboxes,
                mailbox: selectedMailbox,
                nextCursor: result.nextCursor,
                nextPage: result.page + 1,
                previousCursor: result.previousCursor,
                previousPage: Math.max(result.page - 1, 1),
                messages: result.results.map(message => {
                    message.fromHtml = tools.getAddressesHTML(message.from);
                    return message;
                })
            });
        });
    });
}

module.exports = router;

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
        mailbox: Joi.string()
            .hex()
            .length(24),
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

            messageData.html = (messageData.html || []).map(html =>
                html.replace(/attachment:(ATT\d+)/g, (str, aid) => '/webmail/' + mailbox + '/attachment/' + messageData.id + '/' + aid)
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
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.number()
            .min(1)
            .required(),
        attachment: Joi.string()
            .regex(/^ATT\d+$/i)
            .uppercase()
            .required()
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
        mailbox: Joi.string()
            .hex()
            .lowercase()
            .length(24)
            .required(),
        message: Joi.number()
            .min(1)
            .required()
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

router.get('/:mailbox/audit/:message', (req, res, next) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .length(24),
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

            let formatTarget = (target, i) => {
                let seq = leftPad((i + 1).toString(16), '0', 3);
                if (typeof target === 'string') {
                    target = {
                        type: 'mail',
                        text: 'Send to',
                        value: target
                    };
                }
                switch (target.type) {
                    case 'mail':
                        return {
                            seq,
                            num: i + 1,
                            text: target.text || 'Forward to',
                            value: target.value
                        };
                    case 'http':
                        return {
                            seq,
                            num: i + 1,
                            text: 'Upload to',
                            value: target.value
                        };
                    case 'relay':
                        return {
                            seq,
                            num: i + 1,
                            text: 'Relay through',
                            value: target.value.mx[0].exchange + (target.value.mxPort && target.value.mxPort !== 25 ? ':' + target.value.mxPort : '')
                        };
                }
            };

            let forwardTargets = [].concat(messageData.forwardTargets || []).map(formatTarget);

            apiClient.messages.getEvents(req.user.id, mailbox, result.value.message, (err, events) => {
                if (err) {
                    return next(err);
                }

                if (!events) {
                    return res.redirect('/webmail');
                }

                res.render('webmail/audit', {
                    events: events.map(event => {
                        switch (event.action) {
                            case 'STORE':
                                event.actionDescription = 'Message received';
                                event.actionLabel = 'success';
                                break;
                            case 'FORWARD':
                                event.actionDescription = 'Message was queued for forwarding';
                                event.actionLabel = 'info';
                                break;
                            case 'AUTOREPLY':
                                event.actionDescription = 'An autoreply for the message was queued';
                                event.actionLabel = 'info';
                                break;
                            case 'REJECTED':
                                event.actionDescription = 'Message was rejected';
                                event.actionLabel = 'danger';
                                break;
                            case 'ACCEPTED':
                                event.actionDescription = 'Message was accepted';
                                event.actionLabel = 'success';
                                break;
                            case 'QUEUED':
                                event.actionDescription = 'Message was queued for delivery';
                                event.actionLabel = 'success';
                                break;
                            case 'DEFERRED':
                                event.actionDescription = 'Message was temporarily rejected';
                                event.actionLabel = 'warning';
                                break;
                            case 'NOQUEUE':
                                event.actionDescription = 'Failed to queue message';
                                event.actionLabel = 'danger';
                                break;
                            case 'DELETED':
                                event.actionDescription = 'Deleted from queue';
                                event.actionLabel = 'danger';
                                break;
                            case 'DROP':
                                event.actionDescription = 'Dropped from queue';
                                event.actionLabel = 'danger';
                                break;
                            case 'SPAMCHECK':
                                event.actionDescription = 'Messages was checked for spam';
                                event.actionLabel = 'info';
                                break;
                        }

                        if (event.targets) {
                            event.targetList = event.targets.map(formatTarget).filter(target => target);
                        } else if (Array.isArray(event.to) && event.to.length > 1) {
                            event.targetList = event.to.map(formatTarget).filter(target => target);
                            delete event.to;
                        }

                        event.error = event.error || event.reason;

                        return event;
                    }),
                    activeWebmail: true,
                    mailboxes,
                    messageData,
                    mailbox: selectedMailbox,
                    message: result.value.message,
                    forwardTargets
                });
            });
        });
    });
});

function renderMailbox(req, res, next) {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .length(24)
            .empty(''),
        next: Joi.string()
            .max(100)
            .empty(''),
        previous: Joi.string()
            .max(100)
            .empty(''),
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

function leftPad(val, chr, len) {
    return chr.repeat(len - val.toString().length) + val;
}

module.exports = router;

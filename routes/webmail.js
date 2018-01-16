'use strict';

const express = require('express');
const router = new express.Router();
const apiClient = require('../lib/api-client');
const Joi = require('joi');
const tools = require('../lib/tools');
const fs = require('fs');

const templates = {
    messageRowTemplate: fs.readFileSync(__dirname + '/../views/partials/messagerow.hbs', 'utf-8')
};

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
                layout: 'layout-webmail',
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
                    layout: 'layout-webmail',
                    activeWebmail: true,
                    mailboxes,
                    mailbox: selectedMailbox,

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
                            event.toTitle = 'Send to';
                            delete event.to;
                        }

                        event.error = event.error || event.reason;

                        return event;
                    }),
                    messageData,
                    message: result.value.message,
                    forwardTargets
                });
            });
        });
    });
});

router.get('/:mailbox/settings', (req, res, next) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .length(24)
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

        let parents = new Map();

        let mailbox = result.value.mailbox || mailboxes[0].id;
        let mailboxExists = false;
        let selectedMailbox = false;
        let parentPath = false;

        mailboxes.forEach((entry, i) => {
            entry.index = i + 1;

            let parts = entry.path.split('/');
            console.log(parts);
            console.log(parts.slice(0, 1));

            if (entry.id === mailbox) {
                entry.selected = true;
                mailboxExists = true;
                selectedMailbox = entry;
            }

            for (let i = 0; i < parts.length; i++) {
                let path = parts.slice(0, i + 1).join('/');
                let mbox = {
                    id: path === entry.path ? entry.id : false,
                    path,
                    level: i + 1,
                    name: parts.slice(0, i + 1).join(' / '),
                    prefix: '&nbsp;&nbsp;&nbsp;&nbsp'.repeat(i)
                };
                if (entry.path === path && entry.id === mailbox) {
                    continue;
                }
                if (!parents.has(path) || path === entry.path) {
                    parents.set(path, mbox);
                }
            }
        });

        if (selectedMailbox) {
            parentPath = selectedMailbox.path.split('/');
            parentPath.pop();
            parentPath = parentPath.join('/');
        }

        parents = Array.from(parents).map(entry => {
            let parent = entry[1];
            if (parent.path === parentPath) {
                parent.isParent = true;
            }
            return parent;
        });

        if (!mailboxExists) {
            return res.redirect('/webmail');
        }

        console.log(require('util').inspect(mailboxes, false, 22));
        console.log(parents);

        res.render('webmail/mailbox', {
            layout: 'layout-webmail',
            activeWebmail: true,
            mailboxes,
            mailbox: selectedMailbox,

            values: {
                name: selectedMailbox.name
            },

            parents,

            isSpecial: selectedMailbox.path === 'INBOX' || selectedMailbox.specialUse,

            isInbox: selectedMailbox.path === 'INBOX',
            isTrash: selectedMailbox.specialUse === '\\Trash',
            isSent: selectedMailbox.specialUse === '\\Sent',
            isJunk: selectedMailbox.specialUse === '\\Junk',

            csrfToken: req.csrfToken()
        });
    });
});

router.post('/:mailbox/settings', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .length(24),
        parent: Joi.string()
            .default('')
            .allow(''),
        name: Joi.string()
            .regex(/\//, { name: 'folder', invert: true })
            .required()
    });

    req.body.mailbox = req.params.mailbox;
    delete req.body._csrf;

    let result = Joi.validate(req.body, schema, {
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
        return res.redirect('/webmail/' + result.value.mailbox + '/settings');
    }

    let path = result.value.parent
        .split('/')
        .concat(result.value.name.split('/') || [])
        .map(name => name.trim())
        .filter(name => name)
        .join('/');

    apiClient.mailboxes.update(
        req.user.id,
        result.value.mailbox,
        {
            path
        },
        (err, response) => {
            console.log(err || response);

            if (err) {
                req.flash('danger', err.message);
            }

            if (response && response.success) {
                req.flash('success', 'Mailbox folder was updated');
            }

            return res.redirect('/webmail/' + result.value.mailbox + '/settings');
        }
    );
});

router.post('/:mailbox/delete', (req, res) => {
    const schema = Joi.object().keys({
        mailbox: Joi.string()
            .hex()
            .length(24)
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

    apiClient.mailboxes.delete(req.user.id, result.value.mailbox, (err, result) => {
        if (err) {
            req.flash('danger', err.message);
        }

        if (result && result.success) {
            req.flash('success', 'Mailbox folder was deleted');
        }

        return res.redirect('/webmail');
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

    let cursorType, cursorValue;

    if (result.value.next) {
        cursorType = 'next';
        cursorValue = result.value.next;
    } else if (result.value.previous) {
        cursorType = 'previous';
        cursorValue = result.value.previous;
    }

    apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
        if (err) {
            return next(err);
        }

        let mailbox = result.value.mailbox || mailboxes[0].id;
        let mailboxExists = false;
        let selectedMailbox = false;
        mailboxes.forEach((entry, i) => {
            if (entry.path === 'INBOX') {
                entry.specialUse = 'INBOX';
            }
            entry.index = i + 1;
            if (entry.id === mailbox) {
                entry.selected = true;
                mailboxExists = true;
                selectedMailbox = entry;
            } else {
                entry.canMoveTo = true;
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
                layout: 'layout-webmail',
                activeWebmail: true,
                mailboxes,
                mailbox: selectedMailbox,

                cursorType,
                cursorValue,
                page: result.page,
                nextCursor: result.nextCursor,
                nextPage: result.page + 1,
                previousCursor: result.previousCursor,
                previousPage: Math.max(result.page - 1, 1),

                isInbox: selectedMailbox.path === 'INBOX',
                isTrash: selectedMailbox.specialUse === '\\Trash',
                isSent: selectedMailbox.specialUse === '\\Sent',
                isJunk: selectedMailbox.specialUse === '\\Junk',

                messageRowTemplate: templates.messageRowTemplate,
                messages: result.results.map(message => {
                    message.fromHtml = tools.getAddressesHTML(message.from, true);
                    return message;
                }),
                csrfToken: req.csrfToken()
            });
        });
    });
}

function leftPad(val, chr, len) {
    return chr.repeat(len - val.toString().length) + val;
}

module.exports = router;

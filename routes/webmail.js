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

router.get('/create', (req, res) => {
    apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
        if (err) {
            req.flash('danger', err.message);
            res.redirect('/webmail');
            return;
        }

        res.render('webmail/create', {
            layout: 'layout-webmail',
            activeWebmail: true,
            mailboxes: prepareMailboxList(mailboxes),

            values: {
                name: ''
            },
            parents: getParents(mailboxes, false),
            csrfToken: req.csrfToken()
        });
    });
});

router.post('/create', (req, res) => {
    const schema = Joi.object().keys({
        parent: Joi.string()
            .default('')
            .allow(''),
        name: Joi.string()
            .regex(/\//, { name: 'folder', invert: true })
            .required()
    });

    delete req.body._csrf;

    let result = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        allowUnknown: true
    });

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Failed creating mailbox');
        }

        apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
            if (err) {
                req.flash('danger', err.message);
                return res.redirect('/webmail');
            }

            res.render('webmail/create', {
                layout: 'layout-webmail',
                activeWebmail: true,
                mailboxes: prepareMailboxList(mailboxes),

                values: result.value,
                errors,

                parents: getParents(mailboxes, false, result.value.parent),

                csrfToken: req.csrfToken()
            });
        });
    };

    if (result.error) {
        let errors = {};

        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                if (!errors[detail.path]) {
                    errors[detail.path] = detail.message;
                }
            });
        }

        return showErrors(errors);
    }

    let path = result.value.parent
        .split('/')
        .concat(result.value.name.split('/') || [])
        .map(name => name.trim())
        .filter(name => name)
        .join('/');

    apiClient.mailboxes.create(
        req.user.id,
        {
            path
        },
        (err, response) => {
            if (err) {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }

            if (response && response.success) {
                req.flash('success', 'Mailbox folder was created');
            }

            return res.redirect('/webmail/' + response.id);
        }
    );
});

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
                mailboxes: prepareMailboxList(mailboxes),
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
                    mailboxes: prepareMailboxList(mailboxes),
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

        let mailbox = result.value.mailbox || mailboxes[0].id;
        let mailboxExists = false;
        let selectedMailbox = false;

        mailboxes.forEach(entry => {
            if (entry.id === mailbox) {
                entry.selected = true;
                mailboxExists = true;
                selectedMailbox = entry;
            }
        });

        if (!mailboxExists) {
            return res.redirect('/webmail');
        }

        res.render('webmail/mailbox', {
            layout: 'layout-webmail',
            activeWebmail: true,
            mailboxes: prepareMailboxList(mailboxes),
            mailbox: selectedMailbox,

            values: {
                name: selectedMailbox.name
            },

            parents: getParents(mailboxes, selectedMailbox),

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

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Failed updating mailbox');
        }

        apiClient.mailboxes.list(req.user.id, true, (err, mailboxes) => {
            if (err) {
                req.flash('danger', err.message);
                return res.redirect('/webmail');
            }

            let mailbox = result.value.mailbox || mailboxes[0].id;
            let mailboxExists = false;
            let selectedMailbox = false;

            mailboxes.forEach(entry => {
                if (entry.id === mailbox) {
                    entry.selected = true;
                    mailboxExists = true;
                    selectedMailbox = entry;
                }
            });

            if (!mailboxExists) {
                return res.redirect('/webmail');
            }

            res.render('webmail/mailbox', {
                layout: 'layout-webmail',
                activeWebmail: true,
                mailboxes: prepareMailboxList(mailboxes),
                mailbox: selectedMailbox,

                values: result.value,
                errors,

                parents: getParents(mailboxes, selectedMailbox, result.value.parent),

                isSpecial: selectedMailbox.path === 'INBOX' || selectedMailbox.specialUse,

                isInbox: selectedMailbox.path === 'INBOX',
                isTrash: selectedMailbox.specialUse === '\\Trash',
                isSent: selectedMailbox.specialUse === '\\Sent',
                isJunk: selectedMailbox.specialUse === '\\Junk',

                csrfToken: req.csrfToken()
            });
        });
    };

    if (result.error) {
        let errors = {};

        if (result.error && result.error.details) {
            result.error.details.forEach(detail => {
                if (!errors[detail.path]) {
                    errors[detail.path] = detail.message;
                }
            });
        }

        return showErrors(errors);
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
            if (err) {
                req.flash('danger', err.message);
                return showErrors({}, true);
            }

            if (response && response.success) {
                req.flash('success', 'Mailbox settings were updated');
            }

            return res.redirect('/webmail/' + result.value.mailbox);
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
            .allow('starred')
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

        mailboxes = prepareMailboxList(mailboxes);

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
            } else if (typeof entry.canMoveTo === 'undefined') {
                entry.canMoveTo = true;
            }
        });

        if (!mailboxExists) {
            req.flash('danger', 'Selected mailbox does not exist');
            return res.redirect('/webmail');
        }

        selectedMailbox.icon = getIcon(selectedMailbox);

        let makeRequest = done => {
            if (selectedMailbox.id === 'starred') {
                let data = { next: req.query.next, previous: req.query.previous, page: result.value.page || 1, flagged: true, searchable: true };
                return apiClient.messages.search(req.user.id, data, done);
            } else {
                let data = { next: req.query.next, previous: req.query.previous, page: result.value.page || 1 };
                apiClient.messages.list(req.user.id, mailbox, data, done);
            }
        };

        makeRequest((err, result) => {
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

function getParents(mailboxes, mailbox, parentPath) {
    let parents = new Map();

    mailboxes.forEach((entry, i) => {
        if (!entry.path) {
            return;
        }

        let index = i + 1;

        let parts = entry.path.split('/');

        for (let i = 0; i < parts.length; i++) {
            let path = parts.slice(0, i + 1).join('/');
            let mbox = {
                id: path === entry.path ? entry.id : false,
                index,
                path,
                level: i + 1,
                folder: parts[i],
                name: parts.slice(0, i + 1).join(' / ')
            };
            if (mailbox && entry.path === path && entry.id === mailbox.id) {
                // skip current path
                continue;
            }
            if (!parents.has(path) || path === entry.path) {
                parents.set(path, mbox);
            }
        }
    });

    if (mailbox && !parentPath) {
        parentPath = mailbox.path.split('/');
        parentPath.pop();
        parentPath = parentPath.join('/');
    }

    return Array.from(parents).map(entry => {
        let parent = entry[1];
        if (parent.path === parentPath) {
            // immediate parent of current mailbox
            parent.isParent = true;
        }
        return parent;
    });
}

function getIcon(mailbox) {
    if (mailbox.path === 'INBOX') {
        return 'inbox';
    } else if (mailbox.specialUse) {
        switch (mailbox.specialUse) {
            case '\\Trash':
                return 'trash';
            case '\\Sent':
                return 'send';
            case '\\Junk':
                return 'ban-circle';
            case '\\Drafts':
                return 'edit';
            case '\\Archive':
                return 'hdd';
            case 'Starred':
                return 'star';
        }
    }
    return false;
}

function prepareMailboxList(mailboxes, skipStarred) {
    if (!skipStarred) {
        for (let i = 0, len = mailboxes.length; i < len; i++) {
            if (mailboxes[i].path !== 'INBOX' && mailboxes[i].path.indexOf('INBOX/') < 0) {
                mailboxes.splice(i, 0, {
                    id: 'starred',
                    specialUse: 'Starred',
                    path: '',
                    suffix: '',
                    prefix: '',
                    name: 'Starred',
                    formatted: 'Starred',
                    editable: false,
                    canMoveTo: false
                });
                break;
            }
        }
    }

    mailboxes.forEach((mailbox, i) => {
        mailbox.index = i + 1;

        if (mailbox.path) {
            let parts = mailbox.path.split('/');
            let level = 0;

            for (let i = 0; i < parts.length; i++) {
                level++;

                mailbox.formatted = parts[i];
                if (mailbox.path !== 'INBOX') {
                    mailbox.editable = true;
                }

                if (level > 1) {
                    mailbox.prefix = '<div style="padding-left: ' + (level - 1) * 10 + 'px;">';
                    mailbox.suffix = '</div>';
                } else {
                    mailbox.prefix = '';
                    mailbox.suffix = '';
                }
            }
        }

        mailbox.icon = getIcon(mailbox);
    });

    return mailboxes;
}

function leftPad(val, chr, len) {
    return chr.repeat(len - val.toString().length) + val;
}

module.exports = router;

/* eslint no-console: 0 */

'use strict';

const config = require('wild-config');
const request = require('request');
const restify = require('restify-clients');
const client = restify.createJsonClient({
    url: config.api.url
});

module.exports = {
    users: {
        create(data, callback) {
            _exec('post', '/users', false, data, config.api.accessToken, callback);
        },

        get(user, callback) {
            _exec('get', '/users/{user}', { user: user.id }, false, user.token, callback);
        },

        update(user, updates, callback) {
            _exec('put', '/users/{user}', { user: user.id }, updates, user.token, callback);
        },

        authenticate(username, password, sess, ip, callback) {
            _exec(
                'post',
                '/authenticate',
                false,
                {
                    username,
                    password,
                    scope: 'master',
                    sess,
                    appId: config.u2f.appId,
                    token: true,
                    ip
                },
                config.api.accessToken,
                callback
            );
        }
    },

    addresses: {
        list(user, callback) {
            _exec('get', '/users/{user}/addresses', { user: user.id }, false, user.token, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/addresses', { user: user.id }, data, user.token, callback);
        },

        get(user, address, callback) {
            _exec('get', '/users/{user}/addresses/{address}', { user: user.id, address }, false, user.token, callback);
        },

        update(user, address, updates, callback) {
            _exec('put', '/users/{user}/addresses/{address}', { user: user.id, address }, updates, user.token, callback);
        },

        del(user, address, callback) {
            _exec('del', '/users/{user}/addresses/{address}', { user: user.id, address }, false, user.token, callback);
        }
    },

    asps: {
        list(user, callback) {
            _exec('get', '/users/{user}/asps', { user: user.id }, false, user.token, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/asps', { user: user.id }, data, user.token, callback);
        },

        del(user, asp, sess, ip, callback) {
            _exec('del', '/users/{user}/asps/{asp}?ip={ip}', { user: user.id, asp, sess, ip }, false, user.token, callback);
        }
    },

    '2fa': {
        setupTotp(user, issuer, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/setup', { user: user.id }, { issuer, ip }, user.token, callback);
        },

        checkTotp(user, token, sess, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/check', { user: user.id }, { token, sess, ip }, user.token, callback);
        },

        verifyTotp(user, token, sess, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/enable', { user: user.id }, { token, sess, ip }, user.token, callback);
        },

        disable(user, sess, ip, callback) {
            _exec('del', '/users/{user}/2fa?ip={ip}', { user: user.id, sess, ip }, false, user.token, callback);
        },

        setupU2f(user, ip, callback) {
            _exec('post', '/users/{user}/2fa/u2f/setup', { user: user.id }, { ip, appId: config.u2f.appId }, user.token, callback);
        },

        enableU2f(user, requestData, callback) {
            _exec('post', '/users/{user}/2fa/u2f/enable', { user: user.id }, requestData, user.token, callback);
        },

        disableU2f(user, sess, ip, callback) {
            _exec('del', '/users/{user}/2fa/u2f?ip={ip}', { user: user.id, sess, ip }, false, user.token, callback);
        },

        startU2f(user, ip, callback) {
            _exec('post', '/users/{user}/2fa/u2f/start', { user: user.id }, { ip, appId: config.u2f.appId }, user.token, callback);
        },

        checkU2f(user, requestData, callback) {
            _exec('post', '/users/{user}/2fa/u2f/check', { user: user.id }, requestData, user.token, callback);
        }
    },

    authlog: {
        list(user, data, callback) {
            _exec(
                'get',
                '/users/{user}/authlog?next={next}&previous={previous}&page={page}',
                { user: user.id, next: data.next || '', previous: data.previous || '', page: data.page },
                false,
                user.token,
                callback
            );
        },

        get(user, event, callback) {
            _exec('get', '/users/{user}/authlog/{event}', { user: user.id, event }, false, user.token, callback);
        }
    },

    filters: {
        list(user, callback) {
            _exec('get', '/users/{user}/filters', { user: user.id }, false, user.token, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        get(user, filter, callback) {
            _exec('get', '/users/{user}/filters/{filter}', { user: user.id, filter }, false, user.token, callback);
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/filters', { user: user.id }, data, user.token, callback);
        },

        update(user, filter, data, callback) {
            _exec('put', '/users/{user}/filters/{filter}', { user: user.id, filter }, data, user.token, callback);
        },

        del(user, filter, callback) {
            _exec('del', '/users/{user}/filters/{filter}', { user: user.id, filter }, false, user.token, callback);
        }
    },

    mailboxes: {
        list(user, counters, callback) {
            _exec(
                'get',
                '/users/{user}/mailboxes?counters={counters}',
                { user: user.id, counters: counters ? 'true' : 'false' },
                false,
                user.token,
                (err, response) => {
                    if (err) {
                        return callback(err);
                    }
                    return callback(null, (response && response.results) || []);
                }
            );
        },

        get(user, mailbox, args, callback) {
            if (typeof args === 'function' && !callback) {
                callback = args;
                args = false;
            }
            args = args || {};
            args.user = user.id;
            args.mailbox = mailbox;
            _exec('get', '/users/{user}/mailboxes/{mailbox}', args, false, user.token, callback);
        },

        delete(user, mailbox, callback) {
            _exec('del', '/users/{user}/mailboxes/{mailbox}', { user: user.id, mailbox }, false, user.token, callback);
        },

        update(user, mailbox, data, callback) {
            _exec('put', '/users/{user}/mailboxes/{mailbox}', { user: user.id, mailbox }, data, user.token, callback);
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/mailboxes', { user: user.id }, data, user.token, callback);
        }
    },

    autoreply: {
        get(user, callback) {
            _exec('get', '/users/{user}/autoreply', { user: user.id }, false, user.token, callback);
        },

        update(user, data, callback) {
            _exec('put', '/users/{user}/autoreply', { user: user.id }, data, user.token, callback);
        },

        delete(user, callback) {
            _exec('del', '/users/{user}/autoreply', { user: user.id }, false, callback);
        }
    },

    messages: {
        list(user, mailbox, data, callback) {
            data = data || {};
            _exec(
                'get',
                '/users/{user}/mailboxes/{mailbox}/messages?next={next}&previous={previous}&page={page}',
                { user: user.id, mailbox, next: data.next || '', previous: data.previous || '', page: data.page || '', limit: data.limit || '' },
                false,
                user.token,
                callback
            );
        },

        search(user, args, callback) {
            args = args || {};
            args.user = user.id;
            _exec('get', '/users/{user}/search', args, false, user.token, callback);
        },

        get(user, mailbox, message, callback) {
            _exec(
                'get',
                '/users/{user}/mailboxes/{mailbox}/messages/{message}?markAsSeen=true',
                { user: user.id, mailbox, message },
                false,
                user.token,
                callback
            );
        },

        raw(req, res, user, mailbox, message) {
            let options = {
                url: config.api.url + _render('/users/{user}/mailboxes/{mailbox}/messages/{message}/message.eml', { user: user.id, mailbox, message }),
                headers: {
                    'X-Access-Token': user.token
                }
            };
            request(options).pipe(res);
        },

        update(user, mailbox, data, callback) {
            _exec('put', '/users/{user}/mailboxes/{mailbox}/messages', { user: user.id, mailbox }, data, user.token, callback);
        },

        delete(user, mailbox, message, callback) {
            _exec('del', '/users/{user}/mailboxes/{mailbox}/messages/{message}', { user: user.id, mailbox, message }, false, user.token, callback);
        },

        submit(user, data, callback) {
            _exec('post', '/users/{user}/submit', { user: user.id }, data, user.token, callback);
        }
    },

    attachment: {
        get(req, res, user, mailbox, message, attachment) {
            let options = {
                url:
                    config.api.url +
                    _render('/users/{user}/mailboxes/{mailbox}/messages/{message}/attachments/{attachment}', { user: user.id, mailbox, message, attachment }),
                headers: {
                    'X-Access-Token': user.token
                }
            };
            request(options).pipe(res);
        }
    },

    updates: {
        stream(req, res, user) {
            let options = {
                url: config.api.url + _render('/users/{user}/updates', { user: user.id }),
                headers: {
                    'X-Access-Token': user.token
                }
            };
            let stream = request(options);
            stream.pipe(
                res,
                { end: false }
            );
            let stopped = false;
            let stop = err => {
                if (err) {
                    console.error(err);
                }
                if (stopped) {
                    return;
                }
                stopped = true;
                try {
                    stream.abort();
                } catch (E) {
                    console.error(E);
                }
            };

            req.once('end', stop);
            req.once('close', stop);
            req.once('error', stop);
        }
    }
};

function _render(path, args) {
    args = args || {};
    let found = new Set();
    let url = path.replace(/\{([^}]+)\}/g, (match, key) => {
        if (key in args) {
            found.add(key);
            return encodeURIComponent(args[key]);
        }
        return match;
    });

    let get = Object.keys(args || {})
        .filter(key => !found.has(key) && args[key])
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(args[key]))
        .join('&');

    url = url + (get.length ? (url.indexOf('?') < 0 ? '?' : '&') + get : '');
    return url;
}

function _exec(method, path, args, body, token, callback) {
    let req = [
        {
            path: _render(path, args)
        }
    ];

    if (token) {
        req[0].headers = {
            'X-Access-Token': token
        };
    }

    if (body) {
        req.push(body);
    }

    req.push((err, req, res, obj) => {
        if (err) {
            return callback(err);
        }
        if (obj.error) {
            let err = new Error(obj.error);
            if (obj.code) {
                err.code = obj.code;
            }
            return callback(err);
        }

        if (!obj.success) {
            return callback(new Error('Invalid response state'));
        }

        return callback(null, obj);
    });

    client[method](...req);
}

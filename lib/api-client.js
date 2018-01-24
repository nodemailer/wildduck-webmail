/* eslint no-console: 0 */

'use strict';

const config = require('wild-config');
const request = require('request');
const restify = require('restify-clients');
const client = restify.createJsonClient({
    url: config.api.url,
    headers: {
        'X-Access-Token': config.api.accessToken
    }
});

module.exports = {
    users: {
        get(user, callback) {
            _exec('get', '/users/{user}', { user }, false, callback);
        },

        create(data, callback) {
            _exec('post', '/users', false, data, callback);
        },

        update(user, updates, callback) {
            _exec('put', '/users/{user}', { user }, updates, callback);
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
                    ip
                },
                callback
            );
        }
    },

    addresses: {
        list(user, callback) {
            _exec('get', '/users/{user}/addresses', { user }, false, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        }
    },

    asps: {
        list(user, callback) {
            _exec('get', '/users/{user}/asps', { user }, false, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/asps', { user }, data, callback);
        },

        del(user, asp, sess, ip, callback) {
            _exec('del', '/users/{user}/asps/{asp}?ip={ip}', { user, asp, sess, ip }, false, callback);
        }
    },

    '2fa': {
        setupTotp(user, issuer, fresh, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/setup', { user }, { issuer, ip, fresh }, callback);
        },

        checkTotp(user, token, sess, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/check', { user }, { token, sess, ip }, callback);
        },

        verifyTotp(user, token, sess, ip, callback) {
            _exec('post', '/users/{user}/2fa/totp/enable', { user }, { token, sess, ip }, callback);
        },

        disable(user, sess, ip, callback) {
            _exec('del', '/users/{user}/2fa?ip={ip}', { user, sess, ip }, false, callback);
        },

        setupU2f(user, ip, callback) {
            _exec('post', '/users/{user}/2fa/u2f/setup', { user }, { ip }, callback);
        },

        enableU2f(user, requestData, callback) {
            _exec('post', '/users/{user}/2fa/u2f/enable', { user }, requestData, callback);
        },

        disableU2f(user, sess, ip, callback) {
            _exec('del', '/users/{user}/2fa/u2f?ip={ip}', { user, sess, ip }, false, callback);
        },

        startU2f(user, ip, callback) {
            _exec('post', '/users/{user}/2fa/u2f/start', { user }, { ip }, callback);
        },

        checkU2f(user, requestData, callback) {
            _exec('post', '/users/{user}/2fa/u2f/check', { user }, requestData, callback);
        }
    },

    authlog: {
        list(user, data, callback) {
            _exec(
                'get',
                '/users/{user}/authlog?next={next}&previous={previous}&page={page}&sess={sess}',
                { user, next: data.next || '', previous: data.previous || '', page: data.page, sess: data.sess || '' },
                false,
                callback
            );
        },

        get(user, event, callback) {
            _exec('get', '/users/{user}/authlog/{event}', { user, event }, false, callback);
        }
    },

    filters: {
        list(user, callback) {
            _exec('get', '/users/{user}/filters', { user }, false, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        get(user, filter, callback) {
            _exec('get', '/users/{user}/filters/{filter}', { user, filter }, false, callback);
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/filters', { user }, data, callback);
        },

        update(user, filter, data, callback) {
            _exec('put', '/users/{user}/filters/{filter}', { user, filter }, data, callback);
        },

        del(user, filter, callback) {
            _exec('del', '/users/{user}/filters/{filter}', { user, filter }, false, callback);
        }
    },

    mailboxes: {
        list(user, counters, callback) {
            _exec('get', '/users/{user}/mailboxes?counters={counters}', { user, counters: counters ? 'true' : 'false' }, false, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.results) || []);
            });
        },

        delete(user, mailbox, callback) {
            _exec('del', '/users/{user}/mailboxes/{mailbox}', { user, mailbox }, false, callback);
        },

        update(user, mailbox, data, callback) {
            _exec('put', '/users/{user}/mailboxes/{mailbox}', { user, mailbox }, data, callback);
        },

        create(user, data, callback) {
            _exec('post', '/users/{user}/mailboxes', { user }, data, callback);
        }
    },

    autoreply: {
        get(user, callback) {
            _exec('get', '/users/{user}/autoreply', { user }, false, callback);
        },

        update(user, data, callback) {
            _exec('put', '/users/{user}/autoreply', { user }, data, callback);
        },

        delete(user, callback) {
            _exec('del', '/users/{user}/autoreply', { user }, false, callback);
        }
    },

    messages: {
        list(user, mailbox, data, callback) {
            data = data || {};
            _exec(
                'get',
                '/users/{user}/mailboxes/{mailbox}/messages?next={next}&previous={previous}&page={page}',
                { user, mailbox, next: data.next || '', previous: data.previous || '', page: data.page || '', limit: data.limit || '' },
                false,
                callback
            );
        },

        search(user, args, callback) {
            args = args || {};
            args.user = user;
            _exec('get', '/users/{user}/search', args, false, callback);
        },

        get(user, mailbox, message, callback) {
            _exec('get', '/users/{user}/mailboxes/{mailbox}/messages/{message}?markAsSeen=true', { user, mailbox, message }, false, callback);
        },

        getEvents(user, mailbox, message, callback) {
            _exec('get', '/users/{user}/mailboxes/{mailbox}/messages/{message}/events', { user, mailbox, message }, false, (err, response) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, (response && response.events) || []);
            });
        },

        raw(req, res, user, mailbox, message) {
            let options = {
                url: config.api.url + _render('/users/{user}/mailboxes/{mailbox}/messages/{message}/message.eml', { user, mailbox, message }),
                headers: {
                    'X-Access-Token': config.api.accessToken
                }
            };
            request(options).pipe(res);
        },

        update(user, mailbox, message, data, callback) {
            _exec('put', '/users/{user}/mailboxes/{mailbox}/messages/{message}', { user, mailbox, message }, data, callback);
        },

        delete(user, mailbox, message, callback) {
            _exec('del', '/users/{user}/mailboxes/{mailbox}/messages/{message}', { user, mailbox, message }, false, callback);
        },

        submit(user, data, callback) {
            _exec('post', '/users/{user}/submit', { user }, data, callback);
        }
    },

    attachment: {
        get(req, res, user, mailbox, message, attachment) {
            let options = {
                url:
                    config.api.url +
                    _render('/users/{user}/mailboxes/{mailbox}/messages/{message}/attachments/{attachment}', { user, mailbox, message, attachment }),
                headers: {
                    'X-Access-Token': config.api.accessToken
                }
            };
            request(options).pipe(res);
        }
    },

    updates: {
        stream(req, res, user) {
            let options = {
                url: config.api.url + _render('/users/{user}/updates', { user }),
                headers: {
                    'X-Access-Token': config.api.accessToken
                }
            };
            let stream = request(options);
            stream.pipe(res);
            req.once('end', () => {
                try {
                    stream.end();
                } catch (E) {
                    console.log(E);
                }
            });
            req.once('error', err => {
                console.log(err);
                try {
                    stream.end();
                } catch (E) {
                    console.log(E);
                }
            });
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

function _exec(method, path, args, body, callback) {
    let req = [_render(path, args)];

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

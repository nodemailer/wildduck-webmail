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

        authenticate(username, password, ip, callback) {
            _exec(
                'post',
                '/authenticate',
                false,
                {
                    username,
                    password,
                    scope: 'master',
                    ip
                },
                callback
            );
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

        del(user, asp, ip, callback) {
            _exec('del', '/users/{user}/asps/{asp}?ip={ip}', { user, asp, ip }, false, callback);
        }
    },

    '2fa': {
        setup(user, issuer, fresh, ip, callback) {
            _exec('post', '/users/{user}/2fa', { user }, { issuer, ip, fresh }, callback);
        },

        check(user, token, ip, callback) {
            _exec('get', '/users/{user}/2fa?token={token}&ip={ip}', { user, token, ip }, false, callback);
        },

        verify(user, token, ip, callback) {
            _exec('put', '/users/{user}/2fa', { user }, { token, ip }, callback);
        },

        disable(user, ip, callback) {
            _exec('del', '/users/{user}/2fa?ip={ip}', { user, ip }, false, callback);
        }
    },

    authlog: {
        list(user, data, callback) {
            _exec(
                'get',
                '/users/{user}/authlog?next={next}&previous={previous}&page={page}',
                { user, next: data.next || '', previous: data.previous || '', page: data.page },
                false,
                callback
            );
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
                { user, mailbox, next: data.next || '', previous: data.previous || '', page: data.page || '' },
                false,
                callback
            );
        },

        get(user, mailbox, message, callback) {
            _exec('get', '/users/{user}/mailboxes/{mailbox}/messages/{message}?markAsSeen=true', { user, mailbox, message }, false, callback);
        },

        raw(req, res, user, mailbox, message) {
            let options = {
                url: config.api.url + _render('/users/{user}/mailboxes/{mailbox}/messages/{message}/message.eml', { user, mailbox, message }),
                headers: {
                    'X-Access-Token': config.api.accessToken
                }
            };
            request(options).pipe(res);
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
    }
};

function _render(path, args) {
    args = args || {};
    return path.replace(/\{([^}]+)\}/g, (match, key) => {
        if (key in args) {
            return encodeURIComponent(args[key]);
        }
        return match;
    });
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
            return callback(new Error(obj.error));
        }

        if (!obj.success) {
            return callback(new Error('Invalid response state'));
        }

        return callback(null, obj);
    });

    client[method](...req);
}

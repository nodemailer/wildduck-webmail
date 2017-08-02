'use strict';

/**
 * Module dependencies.
 */

let config = require('wild-config');
let log = require('npmlog');
let app = require('./app');
let http = require('http');

let port = config.www.port;
let host = config.www.host;

if (config.title) {
    process.title = config.title;
}

log.level = config.log.level;
app.set('port', port);

/**
 * Create HTTP server.
 */

let server = http.createServer(app);

server.on('error', err => {
    if (err.syscall !== 'listen') {
        throw err;
    }

    let bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;

    // handle specific listen errors with friendly messages
    switch (err.code) {
        case 'EACCES':
            log.error('Express', '%s requires elevated privileges', bind);
            return process.exit(1);
        case 'EADDRINUSE':
            log.error('Express', '%s is already in use', bind);
            return process.exit(1);
        default:
            throw err;
    }
});

server.on('listening', () => {
    let addr = server.address();
    let bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
    log.info('Express', 'WWW server listening on %s', bind);

    if (config.group) {
        try {
            process.setgid(config.group);
            log.info('Service', 'Changed group to "%s" (%s)', config.group, process.getgid());
        } catch (E) {
            log.error('Service', 'Failed to change group to "%s" (%s)', config.group, E.message);
            return process.exit(1);
        }
    }

    if (config.user) {
        try {
            process.setuid(config.user);
            log.info('Service', 'Changed user to "%s" (%s)', config.user, process.getuid());
        } catch (E) {
            log.info('Service', 'Failed to change user to "%s" (%s)', config.user, E.message);
            return process.exit(1);
        }
    }
});

server.listen(port, host);

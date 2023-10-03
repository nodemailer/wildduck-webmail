'use strict';

/**
 * Module dependencies.
 */

const config = require('wild-config');
const log = require('npmlog');
const https = require('https');
const http = require('http');
const db = require('./lib/db');
const fs = require('fs');

const port = config.www.port;
const host = config.www.host;

if (config.title) {
    process.title = config.title;
}

log.level = config.log.level;

// Initialize database connection
db.connect(err => {
    if (err) {
        log.error('Db', 'Failed to setup database connection');
        return process.exit(1);
    }

    const app = require('./app'); // eslint-disable-line global-require
    app.set('port', port);

    /**
     * Create HTTP server.
     */
    let getServer = next => {
        if (config.www.secure) {
            let cert = fs.readFileSync(config.www.cert);
            let key = fs.readFileSync(config.www.key);
            let server = https.createServer({ key, cert }, app);
            return next(null, server);
        }
        next(null, http.createServer(app));
    };

    getServer((err, server) => {
        if (err) {
            throw err;
        }
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
    });
});

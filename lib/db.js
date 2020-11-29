'use strict';

const config = require('wild-config');
const Redis = require('ioredis');

module.exports.redis = false;

module.exports.connect = (callback) => {
    module.exports.redis = new Redis(config.dbs.redis);
    return callback();
};

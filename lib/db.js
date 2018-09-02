'use strict';

const config = require('wild-config');
const mongodb = require('mongodb');
const Redis = require('ioredis');
const MongoClient = mongodb.MongoClient;

module.exports.database = false;
module.exports.redis = false;

let getDBConnection = (main, config, callback) => {
    if (main) {
        if (!config) {
            return callback(null, main);
        }
        if (config && !/[:/]/.test(config)) {
            return callback(null, main.db(config));
        }
    }
    MongoClient.connect(
        config,
        {
            useNewUrlParser: true,
            reconnectTries: 100000,
            reconnectInterval: 1000
        },
        (err, db) => {
            if (err) {
                return callback(err);
            }
            return callback(null, db);
        }
    );
};

module.exports.connect = callback => {
    getDBConnection(false, config.dbs.mongo, (err, db) => {
        if (err) {
            return callback(err);
        }
        module.exports.database = db;

        module.exports.redis = new Redis(config.dbs.redis);

        return callback(null, module.exports.database);
    });
};

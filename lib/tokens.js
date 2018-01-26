'use strict';

const crypto = require('crypto');
const config = require('wild-config');

module.exports.TOKEN_2FA = 0x01;
module.exports.TOKEN_RECOVERY = 0x02;

module.exports.DAYS_2FA = 30;
module.exports.DAYS_RECOVERY = 365;

module.exports.generateToken = (user, scopeCode) => {
    scopeCode = (Number(scopeCode) || 1).toString(16);
    scopeCode = '0'.repeat(5 - scopeCode.length) + scopeCode;
    let parts = [scopeCode, Date.now().toString(16), crypto.randomBytes(6).toString('hex')];

    let valueStr = parts.join('::');
    let hash = crypto
        .createHmac('sha256', config.totp.secret + ':' + user)
        .update(valueStr)
        .digest('hex');

    return valueStr + '::' + hash;
};

module.exports.checkToken = (user, token, scopeCode) => {
    let parts = token.split('::');
    let hash = parts.pop();
    let timestamp = parseInt(parts[1], 16);

    if (parseInt(parts[1], 16) !== scopeCode) {
        return false;
    }

    let days;
    switch (scopeCode) {
        case module.exports.TOKEN_2FA:
            days = module.exports.DAYS_2FA;
            break;
        case module.exports.TOKEN_RECOVERY:
            days = module.exports.DAYS_RECOVERY;
            break;
        default:
            days = 10;
    }

    if (timestamp < Date.now() - days * 24 * 3600 * 1000) {
        return false;
    }

    return (
        hash ===
        crypto
            .createHmac('sha256', config.totp.secret + ':' + user)
            .update(parts.join('::'))
            .digest('hex')
    );
};

'use strict';

const config = require('wild-config');

function getConfig() {
    return config.webauthn || {};
}

module.exports.isEnabled = () => !!getConfig().enabled;

function getRpId(req) {
    let webauthnConfig = getConfig();

    if (webauthnConfig.rpId) {
        return webauthnConfig.rpId;
    }

    return (req.hostname || '').replace(/^\[|\]$/g, '');
}

function getBaseData(req) {
    let data = {
        rpId: getRpId(req),
        sess: req.session.id,
        ip: req.ip
    };

    return data;
}

module.exports.getChallengeData = req => {
    let webauthnConfig = getConfig();
    let data = getBaseData(req);

    data.origin = req.protocol + '://' + req.get('host');
    data.authenticatorAttachment = webauthnConfig.authenticatorAttachment || 'cross-platform';

    return data;
};

module.exports.getVerificationData = getBaseData;

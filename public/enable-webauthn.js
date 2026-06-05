/* eslint-env browser */
/* eslint prefer-arrow-callback: 0, no-var: 0, object-shorthand: 0 */

'use strict';

var message = document.getElementById('message');

function hexToArrayBuffer(hex) {
    var bytes = new Uint8Array(hex.length / 2);

    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }

    return bytes.buffer;
}

function arrayBufferToHex(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = [];

    for (var i = 0; i < bytes.length; i++) {
        hex.push(('00' + bytes[i].toString(16)).slice(-2));
    }

    return hex.join('');
}

function stringToArrayBuffer(str) {
    var bytes = new Uint8Array(str.length);

    for (var i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }

    return bytes.buffer;
}

function showError(err) {
    document.getElementById('webauthn-wait').style.display = 'none';
    document.getElementById('webauthn-fail').style.display = 'block';
    message.classList.add('text-danger');
    message.textContent = err && err.message ? err.message : err;
}

function prepareRegistrationOptions(registrationOptions) {
    var options = Object.assign({}, registrationOptions);

    options.challenge = hexToArrayBuffer(options.challenge);

    if (options.user && typeof options.user.id === 'string') {
        options.user = Object.assign({}, options.user, {
            id: stringToArrayBuffer(options.user.id)
        });
    }

    options.excludeCredentials = (options.excludeCredentials || []).map(function(credential) {
        var result = {
            id: hexToArrayBuffer(credential.rawId || credential.id),
            type: credential.type || 'public-key'
        };

        if (credential.transports) {
            result.transports = credential.transports;
        }

        return result;
    });

    return options;
}

if (window.isSecureContext === false) {
    showError('WebAuthN requires HTTPS or localhost');
} else if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
    showError('WebAuthN is not supported by your browser');
} else {
    document.addEventListener('DOMContentLoaded', function() {
        fetch('/account/security/2fa/setup-webauthn', {
            method: 'post',
            headers: {
                Accept: 'application/json, text/plain, */*',
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ _csrf: document.getElementById('_csrf').value })
        })
            .then(function(res) {
                return res.json();
            })
            .then(function(res) {
                if (res.error) {
                    showError(res.error);
                    return;
                }

                if (!res.registrationOptions) {
                    showError('Did not receive WebAuthN registration options');
                    return;
                }

                var challenge = res.registrationOptions.challenge;
                var rpId = res.registrationOptions.rp && res.registrationOptions.rp.id;
                var publicKey = prepareRegistrationOptions(res.registrationOptions);

                message.textContent = 'Use your security key to continue...';

                return navigator.credentials.create({ publicKey: publicKey }).then(function(credential) {
                    message.textContent = 'Verifying response...';

                    return fetch('/account/security/2fa/enable-webauthn/verify', {
                        method: 'post',
                        headers: {
                            Accept: 'application/json, text/plain, */*',
                            'Content-Type': 'application/json'
                        },
                        credentials: 'include',
                        body: JSON.stringify({
                            _csrf: document.getElementById('_csrf').value,
                            challenge: challenge,
                            rawId: arrayBufferToHex(credential.rawId),
                            clientDataJSON: arrayBufferToHex(credential.response.clientDataJSON),
                            attestationObject: arrayBufferToHex(credential.response.attestationObject),
                            rpId: rpId
                        })
                    });
                });
            })
            .then(function(res) {
                if (!res) {
                    return;
                }

                return res.json();
            })
            .then(function(res) {
                if (!res) {
                    return;
                }

                document.getElementById('webauthn-wait').style.display = 'none';
                if (res.error) {
                    showError(res.error);
                    return;
                }

                document.getElementById('webauthn-success').style.display = 'block';
                message.textContent = res.success ? 'Security key was added to your account' : 'Failed to register security key';
                message.classList.remove('text-danger');

                if (res.success && res.targetUrl) {
                    window.location = res.targetUrl;
                }
            })
            .catch(showError);
    });
}

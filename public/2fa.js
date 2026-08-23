/* eslint-env browser */
/* eslint prefer-arrow-callback: 0, no-var: 0, object-shorthand: 0 */
/* globals $:false, WEBAUTHNSUPPORT: true, loginKeyHandler: false */

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

function webAuthnSupported() {
    return window.isSecureContext !== false && !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
}

function rememberTwoFactor() {
    var remember2fa = document.getElementById('remember2fa');
    return !!(remember2fa && remember2fa.checked);
}

function prepareAuthenticationOptions(authenticationOptions) {
    var options = Object.assign({}, authenticationOptions);

    options.challenge = hexToArrayBuffer(options.challenge);

    options.allowCredentials = (options.allowCredentials || []).map(function(credential) {
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

function enableTotp(e) {
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }

    document.getElementById('show-webauthn').style.display = 'none';
    document.getElementById('show-totp').style.display = 'block';

    document.getElementById('token').focus();
    document.getElementById('token').select();

    WEBAUTHNSUPPORT = false;
}

function startWebAuthn() {
    fetch('/account/start-webauthn', {
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
            if (!WEBAUTHNSUPPORT) {
                return;
            }

            if (res.error) {
                $(message).text(res.error);
                document.getElementById('webauthn-wait').style.display = 'none';
                document.getElementById('webauthn-fail').style.display = 'block';
                message.classList.add('text-danger');
                return;
            }

            if (!res.authenticationOptions) {
                $(message).text('Did not receive WebAuthN authentication options');
                document.getElementById('webauthn-wait').style.display = 'none';
                document.getElementById('webauthn-fail').style.display = 'block';
                message.classList.add('text-danger');
                return;
            }

            var challenge = res.authenticationOptions.challenge;
            var rpId = res.authenticationOptions.rpId;
            var publicKey = prepareAuthenticationOptions(res.authenticationOptions);

            $(message).text('Use your security key to continue...');

            return navigator.credentials.get({ publicKey: publicKey }).then(function(credential) {
                if (!WEBAUTHNSUPPORT) {
                    return;
                }

                $(message).text('Verifying response...');

                var authResponse = {
                    _csrf: document.getElementById('_csrf').value,
                    challenge: challenge,
                    rawId: arrayBufferToHex(credential.rawId),
                    clientDataJSON: arrayBufferToHex(credential.response.clientDataJSON),
                    authenticatorData: arrayBufferToHex(credential.response.authenticatorData),
                    signature: arrayBufferToHex(credential.response.signature),
                    rpId: rpId,
                    remember2fa: rememberTwoFactor() ? 'yes' : ''
                };

                return fetch('/account/check-webauthn', {
                    method: 'post',
                    headers: {
                        Accept: 'application/json, text/plain, */*',
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify(authResponse)
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
            if (!res || !WEBAUTHNSUPPORT) {
                return;
            }

            document.getElementById('webauthn-wait').style.display = 'none';
            if (res.error) {
                $(message).text(res.error);
                message.classList.add('text-danger');
                document.getElementById('webauthn-fail').style.display = 'block';
                return;
            }
            message.classList.remove('text-danger');

            if (res.success && res.remember2fa) {
                loginKeyHandler.set(res.remember2fa.username, res.remember2fa.value, '2fa', res.successlog.days);
            }

            if (res.success && res.successlog) {
                loginKeyHandler.set(res.successlog.username, res.successlog.value, 'recovery', res.successlog.days);
            }

            document.getElementById('webauthn-success').style.display = 'block';
            $(message).text(res.success ? 'You are verified' : 'Failed to check security key');
            if (res.success && res.targetUrl) {
                window.location = res.targetUrl;
            }
        })
        .catch(function() {
            if (!WEBAUTHNSUPPORT) {
                return;
            }

            enableTotp();
        });
}

document.getElementById('enable-totp').addEventListener('click', enableTotp, false);

document.getElementById('totp-form').addEventListener(
    'submit',
    function(e) {
        e.preventDefault();
        e.stopPropagation();

        var body = {
            _csrf: document.getElementById('_csrf').value,
            token: document.getElementById('token').value,
            remember2fa: rememberTwoFactor() ? 'yes' : ''
        };

        var btn = $(document.getElementById('totp-btn'));

        btn.button('loading');
        fetch('/account/check-totp', {
            method: 'post',
            headers: {
                Accept: 'application/json, text/plain, */*',
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(body)
        })
            .then(function(res) {
                return res.json();
            })
            .then(function(res) {
                btn.button('reset');

                if (res.error) {
                    document.getElementById('totp-token-field').classList.add('has-error');
                    $(document.getElementById('totp-token-error')).text(res.error);
                    document.getElementById('totp-token-error').style.display = 'block';
                    document.getElementById('token').focus();
                    document.getElementById('token').select();
                    return;
                }

                document.getElementById('totp-token-field').classList.remove('has-error');
                document.getElementById('totp-token-error').style.display = 'none';

                if (res.success && res.remember2fa) {
                    loginKeyHandler.set(res.remember2fa.username, res.remember2fa.value, '2fa', res.successlog.days);
                }

                if (res.success && res.successlog) {
                    loginKeyHandler.set(res.successlog.username, res.successlog.value, 'recovery', res.successlog.days);
                }

                if (res.success && res.targetUrl) {
                    window.location = res.targetUrl;
                }
            })
            .catch(function(err) {
                btn.button('reset');
                document.getElementById('totp-token-field').classList.add('has-error');
                $(document.getElementById('totp-token-error')).text(err.message);
                document.getElementById('totp-token-error').style.display = 'block';
                document.getElementById('token').focus();
                document.getElementById('token').select();
            });
    },
    false
);

if (WEBAUTHNSUPPORT && webAuthnSupported()) {
    document.addEventListener(
        'DOMContentLoaded',
        function() {
            startWebAuthn();
        },
        false
    );
} else {
    enableTotp();
}

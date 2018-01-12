/* eslint-env browser */
/* eslint prefer-arrow-callback: 0, no-var: 0, object-shorthand: 0 */
/* globals $:false, u2f: false, U2FSUPPORT: false */

'use strict';

var message = document.getElementById('message');

if (U2FSUPPORT) {
    document.addEventListener('DOMContentLoaded', function() {
        fetch('/account/security/2fa/setup-u2f', {
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
                    $(message).text(res.error);
                    message.classList.add('text-danger');
                    document.getElementById('u2f-fail').style.display = 'block';
                    return;
                }

                let appId = res.u2fRegRequest.appId;
                let regRequest = {
                    version: res.u2fRegRequest.version,
                    challenge: res.u2fRegRequest.challenge
                };

                $(message).text('Push the button on your U2F key...');

                u2f.register(appId, [regRequest], [], function(regResponse) {
                    $(message).text('Verifying response...');

                    regResponse._csrf = document.getElementById('_csrf').value;
                    fetch('/account/security/2fa/enable-u2f/verify', {
                        method: 'post',
                        headers: {
                            Accept: 'application/json, text/plain, */*',
                            'Content-Type': 'application/json'
                        },
                        credentials: 'include',
                        body: JSON.stringify(regResponse)
                    })
                        .then(function(res) {
                            return res.json();
                        })
                        .then(function(res) {
                            document.getElementById('u2f-wait').style.display = 'none';
                            if (res.error) {
                                $(message).text(res.error);
                                document.getElementById('u2f-fail').style.display = 'block';
                                message.classList.add('text-danger');
                                return;
                            }
                            document.getElementById('u2f-success').style.display = 'block';
                            $(message).text(res.success ? 'U2F key was added to your account' : 'Failed to register U2F key');
                            message.classList.remove('text-danger');

                            if (res.success && res.targetUrl) {
                                window.location = res.targetUrl;
                            }
                        })
                        .catch(function(err) {
                            $(message).text(err.message);
                            message.classList.add('text-danger');
                        });
                });
            })
            .catch(function(err) {
                $(message).text(err.message);
                message.classList.add('text-danger');
            });
    });
} else {
    document.getElementById('u2f-wait').style.display = 'none';
    document.getElementById('u2f-fail').style.display = 'block';
    message.classList.add('text-danger');
    $(message).text('U2F is not supported by your browser');
}

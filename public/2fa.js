/* eslint-env browser */
/* eslint prefer-arrow-callback: 0, no-var: 0, object-shorthand: 0 */
/* globals $:false, U2FSUPPORT: true, loginKeyHandler: false, u2f: false*/

'use strict';

var message = document.getElementById('message');

function enableTotp(e) {
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }

    document.getElementById('show-u2f').style.display = 'none';
    document.getElementById('show-totp').style.display = 'block';

    document.getElementById('token').focus();
    document.getElementById('token').select();

    U2FSUPPORT = false;
}

function startU2f() {
    fetch('/account/start-u2f', {
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
            if (!U2FSUPPORT) {
                return;
            }

            if (res.error) {
                $(message).text(res.error);
                document.getElementById('u2f-wait').style.display = 'none';
                document.getElementById('u2f-fail').style.display = 'block';
                message.classList.add('text-danger');
                return;
            }

            $(message).text('Push the button on your U2F key...');

            u2f.sign(res.u2fAuthRequest.appId, res.u2fAuthRequest.challenge, [res.u2fAuthRequest], function(authResponse) {
                if (!U2FSUPPORT) {
                    return;
                }

                $(message).text('Verifying response...');

                authResponse._csrf = document.getElementById('_csrf').value;
                authResponse.remember2fa = document.getElementById('remember2fa').checked ? 'yes' : '';

                fetch('/account/check-u2f', {
                    method: 'post',
                    headers: {
                        Accept: 'application/json, text/plain, */*',
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify(authResponse)
                })
                    .then(function(res) {
                        return res.json();
                    })
                    .then(function(res) {
                        if (!U2FSUPPORT) {
                            return;
                        }

                        document.getElementById('u2f-wait').style.display = 'none';
                        if (res.error) {
                            $(message).text(res.error);
                            message.classList.add('text-danger');
                            document.getElementById('u2f-fail').style.display = 'block';
                            return;
                        }
                        message.classList.remove('text-danger');

                        if (res.success && res.remember2fa) {
                            loginKeyHandler.set(res.remember2fa.username, res.remember2fa.value, '2fa', res.successlog.days);
                        }

                        if (res.success && res.successlog) {
                            loginKeyHandler.set(res.successlog.username, res.successlog.value, 'recovery', res.successlog.days);
                        }

                        document.getElementById('u2f-success').style.display = 'block';
                        $(message).text(res.success ? 'You are verified' : 'Failed to check U2F key');
                        if (res.success && res.targetUrl) {
                            window.location = res.targetUrl;
                        }
                    })
                    .catch(function(err) {
                        if (!U2FSUPPORT) {
                            return;
                        }

                        $(message).text(err.message);
                        message.classList.add('text-danger');
                        document.getElementById('u2f-fail').style.display = 'block';
                        return;
                    });
            });
        })
        .catch(function() {
            if (!U2FSUPPORT) {
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
            remember2fa: document.getElementById('remember2fa').checked ? 'yes' : ''
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

if (U2FSUPPORT) {
    document.addEventListener(
        'DOMContentLoaded',
        function() {
            startU2f();
        },
        false
    );
} else {
    enableTotp();
}

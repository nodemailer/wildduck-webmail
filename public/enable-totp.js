/* eslint-env browser */
/* eslint prefer-arrow-callback: 0, no-var: 0, object-shorthand: 0 */
/* globals $:false */

'use strict';

document.getElementById('totp-form').addEventListener(
    'submit',
    function(e) {
        e.preventDefault();
        e.stopPropagation();

        var body = {
            _csrf: document.getElementById('_csrf').value,
            token: document.getElementById('token').value
        };

        var btn = $(document.getElementById('totp-btn'));

        btn.button('loading');
        fetch('/account/security/2fa/verify-totp', {
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

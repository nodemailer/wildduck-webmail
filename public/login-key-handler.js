/* eslint-env browser */
/* eslint no-bitwise: 0, no-var: 0, object-shorthand: 0, prefer-arrow-callback: 0 */
// this script handle

'use strict';

window.loginKeyHandler = {
    setup: function(usernameElm, valueElm, scope) {
        var that = this;
        var formElm = usernameElm.form;
        if (!formElm) {
            throw new Error('Form element was not found for username element');
        }

        formElm.addEventListener(
            'submit',
            function() {
                var username = (usernameElm.value || '').toString();
                if (!username) {
                    return;
                }
                var valueStr = that.get(username, scope);
                if (valueStr) {
                    valueElm.value = valueStr;
                }
            },
            false
        );
    },

    get: function(username, scope) {
        scope = (scope || '').toString() || 'default';
        username = (username || '')
            .toString()
            .toLowerCase()
            .replace(/^\s+|\s+$/g, '');

        var data = this.loadData(scope);
        if (!data || !data.keys.length || !username) {
            // failed to access storage
            return false;
        }
        var entry;
        var hash;
        for (var i = 0, len = data.keys.length; i < len; i++) {
            entry = data.keys[i];
            if (!entry || !entry.hash || !entry.seed || typeof entry.seed !== 'number') {
                continue;
            }
            hash = this.murmurhash2_32_gc(username, entry.seed);
            if (hash !== entry.hash) {
                continue;
            }

            if (entry.expires && entry.expires < new Date().getTime()) {
                // found a match but it was expired
                data.keys.splice(i, 1);
                this.storeData(scope, data);
                return false;
            }
            // found a probable match
            return entry.value;
        }
        return false;
    },

    set: function(username, value, scope, expireDays) {
        scope = (scope || '').toString() || 'default';
        username = (username || '')
            .toString()
            .toLowerCase()
            .replace(/^\s+|\s+$/g, '');

        var min = 0x01000000;
        var max = 0xffffffff;

        expireDays = expireDays || 30;

        var data = this.loadData(scope);
        if (!data || !data.keys || !username) {
            // failed to access storage
            return false;
        }

        var entry;
        var hash;
        var seed;
        var curTime = new Date().getTime();

        // remove old entries
        for (var i = data.keys.length - 1; i >= 0; i--) {
            entry = data.keys[i];
            if (!entry || !entry.hash || !entry.seed || typeof entry.seed !== 'number') {
                continue;
            }
            if (entry.expires && entry.expires < curTime) {
                // remove expired data
                data.keys.splice(i, 1);
                continue;
            }

            hash = this.murmurhash2_32_gc(username, entry.seed);
            if (hash !== entry.hash) {
                continue;
            }

            // remove existing match
            data.keys.splice(i, 1);
        }

        // add new entry
        seed = Math.floor(Math.random() * (max - min + 1) + min);
        entry = {
            hash: this.murmurhash2_32_gc(username, seed),
            seed: seed,
            value: value,
            created: new Date().getTime()
        };

        entry.expires = entry.created + expireDays * 24 * 3600 * 1000;

        data.keys.push(entry);
        return this.storeData(scope, data);
    },

    loadData: function(scope) {
        var key = 'id:' + scope + ':data';
        var dataStr, data;

        try {
            dataStr = localStorage.getItem(key);
        } catch (E) {
            // failed to access local storage
            return false;
        }

        if (dataStr !== null) {
            try {
                data = JSON.parse(dataStr);
            } catch (E) {
                // invalid JSON
            }
        }

        if (!data || typeof data !== 'object' || data.scope !== scope) {
            data = {
                scope: scope,
                keys: []
            };
        }
        if (!data.keys || Object.prototype.toString.call(data.keys) !== '[object Array]') {
            data.keys = [];
        }

        return data;
    },

    storeData: function(scope, data) {
        var key = 'id:' + scope + ':data';
        var dataStr = JSON.stringify(data);

        try {
            localStorage.setItem(key, dataStr);
        } catch (E) {
            // failed to access local storage
            return false;
        }

        return data.keys.length;
    },

    /**
     * JS Implementation of MurmurHash2
     *
     *  SOURCE: https://github.com/garycourt/murmurhash-js (MIT licensed)
     *
     * @author <a href='mailto:gary.court@gmail.com'>Gary Court</a>
     * @see http://github.com/garycourt/murmurhash-js
     * @author <a href='mailto:aappleby@gmail.com'>Austin Appleby</a>
     * @see http://sites.google.com/site/murmurhash/
     *
     * @param {string} str ASCII only
     * @param {number} seed Positive integer only
     * @return {number} 32-bit positive integer hash
     */

    murmurhash2_32_gc: function(str, seed) {
        var l = str.length,
            h = seed ^ l,
            i = 0,
            k;

        while (l >= 4) {
            k = (str.charCodeAt(i) & 0xff) | ((str.charCodeAt(++i) & 0xff) << 8) | ((str.charCodeAt(++i) & 0xff) << 16) | ((str.charCodeAt(++i) & 0xff) << 24);

            k = (k & 0xffff) * 0x5bd1e995 + ((((k >>> 16) * 0x5bd1e995) & 0xffff) << 16);
            k ^= k >>> 24;
            k = (k & 0xffff) * 0x5bd1e995 + ((((k >>> 16) * 0x5bd1e995) & 0xffff) << 16);

            h = ((h & 0xffff) * 0x5bd1e995 + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16)) ^ k;

            l -= 4;
            ++i;
        }

        switch (l) {
            case 3:
                h ^= (str.charCodeAt(i + 2) & 0xff) << 16;
            /* falls through */
            case 2:
                h ^= (str.charCodeAt(i + 1) & 0xff) << 8;
            /* falls through */
            case 1:
                h ^= str.charCodeAt(i) & 0xff;
                h = (h & 0xffff) * 0x5bd1e995 + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16);
        }

        h ^= h >>> 13;
        h = (h & 0xffff) * 0x5bd1e995 + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16);
        h ^= h >>> 15;

        return h >>> 0;
    }
};

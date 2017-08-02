/* eslint-env browser */
/* global moment: false*/

'use strict';

function updateDatestrings() {
    let elms = document.querySelectorAll('.datestring');
    let elm;

    for (let i = 0, len = elms.length; i < len; i++) {
        elm = elms[i];
        if (elm.title && elm.title.length === 24) {
            //elm.textContent = moment(elm.title).format('YYYY-MM-DD HH:mm:ss');
            elm.textContent = moment(elm.title).calendar(null, {
                lastDay: '[Yesterday at] LT',
                sameDay: '[Today at] LT',
                nextDay: '[Tomorrow at] LT',
                lastWeek: '[last] dddd [at] LT',
                nextWeek: 'dddd [at] LT',
                sameElse: 'DD/MM/YYYY LT'
            });
        }
    }
}

function updateFixedDatestrings() {
    let elms = document.querySelectorAll('.datestring-fixed');
    let elm;

    for (let i = 0, len = elms.length; i < len; i++) {
        elm = elms[i];
        if (elm.title && elm.title.length === 13) {
            elm.textContent = moment(Number(elm.title)).format('YYYY-MM-DD HH:mm');
        }
    }
}

function updateRelativeDatestrings() {
    let elms = document.querySelectorAll('.datestring-relative');
    let elm;

    for (let i = 0, len = elms.length; i < len; i++) {
        elm = elms[i];
        if (elm.title && elm.title.length === 24) {
            elm.textContent = moment(elm.title).fromNow();
        }
    }
}

// moment.locale('et');
moment.updateLocale('en', {
    longDateFormat: {
        LT: 'H:mm',
        LTS: 'H:mm:ss',
        L: 'DD.MM.YYYY',
        LL: 'D. MMMM YYYY',
        LLL: 'D. MMMM YYYY H:mm',
        LLLL: 'dddd, D. MMMM YYYY H:mm'
    }
});

updateDatestrings();
updateFixedDatestrings();
updateRelativeDatestrings();

setInterval(updateRelativeDatestrings, 10 * 1000);
setInterval(updateDatestrings, 60 * 1000);

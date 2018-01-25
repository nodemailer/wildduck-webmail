'use strict';

const punycode = require('punycode');
const he = require('he');

function getAddressesHTML(value, noLinks) {
    let formatSingleLevel = addresses =>
        addresses
            .map(address => {
                let str = '<span class="mp_address_group">';
                /*
                if (address.name) {

                    str += '<span class="mp_address_name">' + he.encode(address.name) + (address.group ? ': ' : '') + '</span>';
                }
                */
                if (address.address) {
                    let link;
                    if (noLinks) {
                        link =
                            '<span class="mp_address_email" rel="tooltip" title="' +
                            he.encode(address.address) +
                            '">' +
                            he.encode(address.name || address.address) +
                            '</span>';
                    } else {
                        link =
                            '<a href="/webmail/send?to=' +
                            he.encode(address.address) +
                            '" class="mp_address_email" rel="tooltip" title="' +
                            he.encode(address.address) +
                            '">' +
                            he.encode(address.name || address.address) +
                            '</a>';
                    }
                    //if (!address.name) {
                    //    str += ' &lt;' + link + '&gt;';
                    //} else {
                    str += link;
                    //}
                }
                if (address.group) {
                    str += formatSingleLevel(address.group) + ';';
                }
                return str + '</span>';
            })
            .join(', ');
    return formatSingleLevel([].concat(value || []));
}

function normalizeDomain(domain) {
    domain = (domain || '').toLowerCase().trim();
    try {
        if (/^xn--/.test(domain)) {
            domain = punycode
                .toUnicode(domain)
                .normalize('NFC')
                .toLowerCase()
                .trim();
        }
    } catch (E) {
        // ignore
    }

    return domain;
}

function normalizeAddress(address, withNames, options) {
    if (typeof address === 'string') {
        address = {
            address
        };
    }
    if (!address || !address.address) {
        return '';
    }

    options = options || {};

    let removeLabel = typeof options.removeLabel === 'boolean' ? options.removeLabel : false;
    let removeDots = typeof options.removeDots === 'boolean' ? options.removeDots : false;

    let user = address.address
        .substr(0, address.address.lastIndexOf('@'))
        .normalize('NFC')
        .toLowerCase()
        .trim();

    if (removeLabel) {
        user = user.replace(/\+[^@]*$/, '');
    }

    if (removeDots) {
        user = user.replace(/\./g, '');
    }

    let domain = normalizeDomain(address.address.substr(address.address.lastIndexOf('@') + 1));

    let addr = user + '@' + domain;

    if (withNames) {
        return {
            name: address.name || '',
            address: addr
        };
    }

    return addr;
}

module.exports = {
    getAddressesHTML,
    normalizeAddress,
    normalizeDomain
};

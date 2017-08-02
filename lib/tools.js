'use strict';

const he = require('he');

function getAddressesHTML(value) {
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
                    let link =
                        '<a href="mailto:' +
                        he.encode(address.address) +
                        '" class="mp_address_email" rel="tooltip" title="' +
                        he.encode(address.address) +
                        '">' +
                        he.encode(address.name || address.address) +
                        '</a>';
                    if (!address.name) {
                        str += ' &lt;' + link + '&gt;';
                    } else {
                        str += link;
                    }
                }
                if (address.group) {
                    str += formatSingleLevel(address.group) + ';';
                }
                return str + '</span>';
            })
            .join(', ');
    return formatSingleLevel([].concat(value || []));
}

module.exports = {
    getAddressesHTML
};

"use strict";

const pkijs = require("pkijs");
const asn1js = require("asn1js");

function getOidForDnAttribute(attr) {
    switch (attr.toUpperCase()) {
        // RFC 5280 (4.1.2.4) attributes listed as MUST support:
        // * country,
        case "C":
            return "2.5.4.6";
        // * organization,
        case "O":
            return "2.5.4.10";
        // * organizational unit,
        case "OU":
            return "2.5.4.11";
        // * distinguished name qualifier,
        case "dnQualifier":
            return "2.5.4.46";
        // * state or province name,
        case "ST":
        case "S":
            return "2.5.4.8";
        // * common name(e.g., "Dan Peterson"), and
        case "CN":
            return "2.5.4.3";
        // * serial number.
// ReSharper disable once StringLiteralTypo
        case "SERIALNUMBER":
            return "2.5.4.5";

        // RFC 5280 (4.1.2.4) attributes listed as SHOULD support:
        // * locality,
        case "L":
            return "2.5.4.7";
        // * title,
        case "T":
        case "TITLE":
            return "2.5.4.12";
        // * surname,
        case "SN":
            return "2.5.4.4";
        // * given name,
        case "G":
            return "2.5.4.42";
        // * initials,
        case "I":
            return "2.5.4.43";
        // * pseudonym, and
        case "2.5.4.65":
            return "2.5.4.65";
        //  * generation qualifier(e.g., "Jr.", "3rd", or "IV").
        case "2.5.4.44":
            return "2.5.4.44";

        // Also...
        // * domain component
        case "DC":
            return "0.9.2342.19200300.100.1.25";
        // * email address
        case "E":
            return "1.2.840.113549.1.9.1";
        // * rfc822Mailbox
        case "MAIL":
            return "0.9.2342.19200300.100.1.3";
        // * user ID
        case "UID":
            return "0.9.2342.19200300.100.1.1";
// ReSharper disable once StringLiteralTypo
        case "UNSTRUCTUREDNAME":
            return "1.2.840.113549.1.9.2";
// ReSharper disable once StringLiteralTypo
        case "UNSTRUCTUREDADDRESS":
            return "1.2.840.113549.1.9.8";
        default:
            throw new Error(`Unknown DN attribute ${attr}`);
    }
}

exports.beautifyDistinguishedName = (dnString) => {
    let prettyDn = "";
    dnString.split(",").forEach(function(dnPart) {
        const [attr, value] = dnPart.split("=");
        if (!attr || !value)
            throw new Error(`distinguishedName ${dnPart} did not parse`);
        prettyDn = prettyDn.concat(`${attr.toUpperCase()}=${value},`);
    });
    return prettyDn.slice(0, -1);
}

exports.createDistinguishedName = (dnString) => {
    const relativeNames = [];
    dnString.split(",").forEach(function(dnPart) {
        const [attr, value] = dnPart.split("=");
        if (!attr || !value)
            throw new Error(`distinguishedName ${dnPart} did not parse`);
        relativeNames.push(new pkijs.AttributeTypeAndValue({
            type: getOidForDnAttribute(attr),
            value: new asn1js.PrintableString({ value: value })
        }));
    });
    if (relativeNames.length === 0) {
        throw new Error(`Unable to parse distinguished name from ${dnString}`);
    }
    return relativeNames;
}

exports.getCertificateDateRange = (numDays) => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const expire = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    expire.setDate(expire.getDate() + numDays);
    return [today, expire];
}

exports.convertToPem = (label, berArray) => {
    if (!label || !berArray)
        throw new Error("Both the label and the BER array are required to generate PEM.")
    const octetString = String.fromCharCode.apply(null, new Uint8Array(berArray));
    const b64String = btoa(octetString);
    const stringLength = b64String.length;
    let resultString = `-----BEGIN ${label.toUpperCase()}-----\r\n`;
    for (let i = 0, count = 0; i < stringLength; i++ , count++) {
        if (count > 63) {
            resultString = `${resultString}\r\n`;
            count = 0;
        }
        resultString = `${resultString}${b64String[i]}`;
    }
    return resultString + `\r\n-----END ${label.toUpperCase()}-----`;
}
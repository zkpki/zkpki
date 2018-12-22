"use strict";

let conversions = require("./conversions.js");

let zkPkiCert = function (parameters = {}) {
    if (parameters.certificatePemData !== undefined) {
        this.certificatePemData = parameters.certificatePemData;
    } else {
        this.certificatePemData = null;
    }
    if (parameters.privateKeyPemData !== undefined) {
        this.privateKeyPemData = parameters.privateKeyPemData;
    } else {
        this.privateKeyPemData = null;
    }
    if (parameters.certificate !== undefined) {
        this.certificate = parameters.certificate;
    } else {
        this.certificate = null;
    }
}

Object.defineProperty(zkPkiCert.prototype, "serialNumber", {
    get: function serialNumber() {
        return this.certificate.serialNumber.valueBlock.valueDec; 
    }
});
Object.defineProperty(zkPkiCert.prototype, "subject", {
    get: function subject() {
        return conversions.dnTypesAndValuesToString(this.certificate.subject.typesAndValues);
    }
});
Object.defineProperty(zkPkiCert.prototype, "issuer", {
    get: function issuer() {
        return conversions.dnTypesAndValuesToString(this.certificate.issuer.typesAndValues);
    }
});
Object.defineProperty(zkPkiCert.prototype, "issueDate", {
    get: function issueDate() {
        return this.certificate.notBefore.value;
    }
});
Object.defineProperty(zkPkiCert.prototype, "expirationDate", {
    get: function expirationDate() {
        return this.certificate.notAfter.value;
    }
});

module.exports = zkPkiCert;

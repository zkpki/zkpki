"use strict";

const certUtil = require("../cert-util");

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

Object.defineProperty(zkPkiCert.prototype, "checkContainsRaw", {
    enumerable: false,
    value: function checkContainsRaw() {
        if (this.certificate === null) {
            throw Error("ZkPkiCert does not contain raw certificate.");
        }
    }
});

Object.defineProperty(zkPkiCert.prototype, "serialNumber", {
    get: function serialNumber() {
        this.checkContainsRaw();
        return this.certificate.serialNumber.valueBlock.valueDec; 
    }
});
Object.defineProperty(zkPkiCert.prototype, "subject", {
    get: function subject() {
        this.checkContainsRaw();
        return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.subject.typesAndValues);
    }
});
Object.defineProperty(zkPkiCert.prototype, "issuer", {
    get: function issuer() {
        this.checkContainsRaw();
        return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.issuer.typesAndValues);
    }
});
Object.defineProperty(zkPkiCert.prototype, "issueDate", {
    get: function issueDate() {
        this.checkContainsRaw();
        return this.certificate.notBefore.value;
    }
});
Object.defineProperty(zkPkiCert.prototype, "expirationDate", {
    get: function expirationDate() {
        this.checkContainsRaw();
        return this.certificate.notAfter.value;
    }
});
// TODO: add algorithm and key size

module.exports = zkPkiCert;

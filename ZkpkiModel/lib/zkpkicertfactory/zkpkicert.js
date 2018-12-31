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

Object.defineProperty(zkPkiCert.prototype,
    "checkContainsRaw",
    {
        enumerable: false,
        value: function checkContainsRaw() {
            if (this.certificate === null) {
                throw Error("ZkPkiCert does not contain raw certificate.");
            }
        }
    });

Object.defineProperty(zkPkiCert.prototype,
    "serialNumber",
    {
        get: function serialNumber() {
            this.checkContainsRaw();
            const b64String = Array.prototype.map.call(
                new Uint8Array(this.certificate.serialNumber.valueBlock.valueHex),
                x => ("00" + x.toString(16)).slice(-2)).join('');
            return b64String.replace(/^0+/, ""); // remove leading zeros if present
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "subject",
    {
        get: function subject() {
            this.checkContainsRaw();
            return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.subject.typesAndValues);
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "issuer",
    {
        get: function issuer() {
            this.checkContainsRaw();
            return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.issuer.typesAndValues);
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "issueDate",
    {
        get: function issueDate() {
            this.checkContainsRaw();
            return this.certificate.notBefore.value;
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "expirationDate",
    {
        get: function expirationDate() {
            this.checkContainsRaw();
            return this.certificate.notAfter.value;
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "publicKeyAlgorithm",
    {
        get: function publicKeyAlgorithm() {
            this.checkContainsRaw();
            return certUtil.conversions.algorithmOidToAlgorithmName(
                this.certificate.subjectPublicKeyInfo.algorithm.algorithmId);
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "publicKeySize",
    {
        get: function publicKeySize() {
            this.checkContainsRaw();
            switch (this.publicKeyAlgorithm) {
                case certUtil.ALGORITHMS.RsaSsaPkcs1V1_5:
                case certUtil.ALGORITHMS.RsaPss:
                    return this.certificate.subjectPublicKeyInfo.parsedKey.modulus.valueBlock.valueHex.byteLength * 8;
                case certUtil.ALGORITHMS.Ecdsa:
                    return 0;
                default:
                    return 0;
            }
        }
    });


module.exports = zkPkiCert;

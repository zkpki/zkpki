"use strict";

const certUtil = require("../cert-util");
const rawCert = require("./rawcert.js");

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
    if (parameters.privateKey !== undefined) {
        this.privateKey = parameters.privateKey;
    } else {
        this.privateKey = null;
    }
}

Object.defineProperty(zkPkiCert.prototype,
    "checkContainsRawCertificate",
    {
        enumerable: false,
        value: function checkContainsRawCertificate() {
            if (this.certificate === null) {
                throw Error("ZkPkiCert does not contain raw certificate.");
            }
        }
    });

Object.defineProperty(zkPkiCert.prototype,
    "checkContainsRawPrivateKey",
    {
        enumerable: false,
        value: function checkContainsRawPrivateKey() {
            if (this.privateKey === null) {
                throw Error("ZkPkiCert does not contain raw private key.");
            }
        }
    });


Object.defineProperty(zkPkiCert.prototype,
    "toPkcs12",
    {
        enumerable: false,
        value: async function toPkcs12() {
            this.checkContainsRawPrivateKey();
            // TODO:
        }
    });

Object.defineProperty(zkPkiCert.prototype,
    "getCryptoPrivateKey",
    {
        enumerable: false,
        value: async function getCryptoPrivateKey() {
            this.checkContainsRawPrivateKey();
            return await rawCert.importRsaPrivateKey(this.privateKey.toSchema().toBER(), this.publicKeyAlgorithm);
        }
    });

Object.defineProperty(zkPkiCert.prototype,
    "serialNumber",
    {
        get: function serialNumber() {
            this.checkContainsRawCertificate();
            const b64String = Array.prototype.map.call(
                new Uint8Array(this.certificate.serialNumber.valueBlock.valueHex),
                x => (`00${x.toString(16)}`).slice(-2)).join("");
            return b64String.replace(/^0+/, ""); // remove leading zeros if present
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "subject",
    {
        get: function subject() {
            this.checkContainsRawCertificate();
            return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.subject.typesAndValues);
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "issuer",
    {
        get: function issuer() {
            this.checkContainsRawCertificate();
            return certUtil.conversions.dnTypesAndValuesToDnString(this.certificate.issuer.typesAndValues);
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "issueDate",
    {
        get: function issueDate() {
            this.checkContainsRawCertificate();
            return this.certificate.notBefore.value;
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "keyUsages",
    {
        get: function keyUsages() {
            this.checkContainsRawCertificate();
            return certUtil.conversions.keyUsagesAsArrayOfStrings(
                this.extensions.filter(ext => ext.extnID === "2.5.29.15"));
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "extendedKeyUsages",
    {
        get: function extendedKeyUsages() {
            this.checkContainsRawCertificate();
            return certUtil.conversions.extendedKeyUsagesAsArrayOfStrings(
                this.extensions.filter(ext => ext.extnID === "2.5.29.37"));
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "expirationDate",
    {
        get: function expirationDate() {
            this.checkContainsRawCertificate();
            return this.certificate.notAfter.value;
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "publicKeyAlgorithm",
    {
        get: function publicKeyAlgorithm() {
            this.checkContainsRawCertificate();
            const algorithmName = certUtil.conversions.algorithmOidToAlgorithmName(
                this.certificate.subjectPublicKeyInfo.algorithm.algorithmId);
            if (algorithmName === certUtil.ALGORITHMS.RsaSsaPkcs1V1_5)
                // get the specific RSA signature algorithm used to sign this certificate
                return certUtil.conversions.algorithmOidToAlgorithmName(
                    this.certificate.signatureAlgorithm.algorithmId);
            return algorithmName;
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "publicKeySize",
    {
        get: function publicKeySize() {
            this.checkContainsRawCertificate();
            switch (this.publicKeyAlgorithm) {
                case certUtil.ALGORITHMS.RsaSsaPkcs1V1_5:
                case certUtil.ALGORITHMS.RsaPss:
                    return this.certificate.subjectPublicKeyInfo
                        .parsedKey.modulus.valueBlock.valueHex.byteLength * 8;
                case certUtil.ALGORITHMS.Ecdsa:
                    return 0;
                default:
                    return 0;
            }
        }
    });
Object.defineProperty(zkPkiCert.prototype,
    "ellipticCurveName",
    {
        get: function ellipticCurveName() {
            this.checkContainsRawCertificate();
            switch (this.publicKeyAlgorithm) {
                case certUtil.ALGORITHMS.RsaSsaPkcs1V1_5:
                case certUtil.ALGORITHMS.RsaPss:
                    return "";
                case certUtil.ALGORITHMS.Ecdsa:
                    return certUtil.conversions.curveOidToCurveName(
                        this.certificate.subjectPublicKeyInfo.parsedKey.namedCurve);
                default:
                    return "";
            }
        }
    });


module.exports = zkPkiCert;

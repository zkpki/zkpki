"use strict";

function validateCertificateParameters(parameters) {
    if (!Number.isInteger(parameters.serialNumber))
        throw new Error("serialNumber option is required and must be an integer");
    if (!Number.isInteger(parameters.lifetimeDays))
        throw new Error("lifetimeDays option is required and must be an integer");
    if (!parameters.issuerDn)
        throw new Error("issuerDn option is required");
    if (!parameters.subjectDn)
        throw new Error("subjectDn option is required");
    if (parameters.subjectAlterativeNames) {
        if (!Array.isArray(parameters.subjectAlternativeNames))
            throw new Error("subjectAlternativeNames option must be an array");
        parameters.subjectAlternativeNames.forEach(sAN => {
            if (!("ip" in sAN || "dns" in sAN)) {
                throw new Error(
                    "subjectAlternativeNames option is an array of objects with a single property, "
                    + "where that property is either 'ip' or 'dns'");
            }
        });
    }
}

function validateCertificateSigningRequest(csrPemData) {
    // TODO: write this
}

let ZkPkiCertFactory = function () {
    const certUtil = require("../cert-util");
    const rawCert = require("./rawcert.js");
    const ZkPkiCert = require("./zkpkicert.js");

    // private functions
    async function generateKeyPair(algorithm, keySizeOrCurveName) {
        let keyPair = null;
        switch (algorithm) {
        case certUtil.ALGORITHMS.RsaSsaPkcs1V1_5:
        case certUtil.ALGORITHMS.RsaPss:
            keyPair = await rawCert.generateRsaKeyPair(algorithm || certUtil.ALGORITHMS.RsaSsaPkcs1V1_5,
                keySizeOrCurveName || 2048);
            break;
        case certUtil.ALGORITHMS.Ecdsa:
            keyPair = await rawCert.generateEcdsaKeyPair(
                keySizeOrCurveName || certUtil.ELLIPTIC_CURVE_NAMES.NistP256);
            break;
        default:
            throw new Error(`Unknown algorithm name: ${algorithm}`);
        }
        return keyPair;
    }

    // constants
    const startingSerialNumber = 100000;

    // load zkpki certificate from PEM data or raw pkijs
    this.loadCertificate = async (data = {}) => {
        let zkPkiCert = new ZkPkiCert(data);

        // because some logic using pkijs below requires async functions
        // we have to put this logic here rather than in the ZkPkiCert constructor

        // certificate
        if (zkPkiCert.certificatePemData === null && zkPkiCert.certificate === null) {
            throw new Error("Unable to create ZkPkiCert with no certificate object and no PEM");
        } else if (zkPkiCert.certificatePemData === null && zkPkiCert.certificate !== null) {
            zkPkiCert.certificatePemData = certUtil.conversions.berToPem("CERTIFICATE",
                zkPkiCert.certificate.toSchema(true).toBER(false));
        } else if (zkPkiCert.certificatePemData !== null && zkPkiCert.certificate === null) {
            zkPkiCert.certificate = rawCert.parseRawCertificate(certUtil.conversions.pemToBer(zkPkiCert.certificatePemData));
        }

        // private key
        if (zkPkiCert.privateKeyPemData === null && zkPkiCert.privateKey !== null) {
            zkPkiCert.privateKeyPemData =
                certUtil.conversions.berToPem("PRIVATE KEY", await rawCert.exportPrivateKey(zkPkiCert.privateKey));
        } else if (zkPkiCert.privateKeyPemData !== null && zkPkiCert.privateKey === null) {
            const privateKeyData = certUtil.conversions.pemToBer(zkPkiCert.privateKeyPemData);
            zkPkiCert.privateKey = rawCert.parseRawPrivateKey(privateKeyData);
        }
        return zkPkiCert;
    }

    // create zkpki root certificate authority
    this.createCertificateAuthority = async (distinguishedName, lifetimeDays, algorithm, keySizeOrCurveName) => {
        const keyPair = await generateKeyPair(algorithm, keySizeOrCurveName);
        const zkPkiCert = await this.loadCertificate({
            certificate: await rawCert.createRawCertificate(keyPair,
                keyPair.publicKey,
                {
                    serialNumber: startingSerialNumber,
                    issuerDn: distinguishedName,
                    subjectDn: distinguishedName,
                    lifetimeDays: lifetimeDays || (365 * 10),
                    isCa: true,
                    keyUsages: certUtil.KEY_USAGES.KeySignCert | certUtil.KEY_USAGES.CrlSign,
                    extendedKeyUsages: [
                        certUtil.EXTENDED_KEY_USAGES.MsCertificateTrustListSigning,
                        certUtil.EXTENDED_KEY_USAGES.ServerAuthentication,
                        certUtil.EXTENDED_KEY_USAGES.ClientAuthentication,
                        certUtil.EXTENDED_KEY_USAGES.OcspSigning,
                        certUtil.EXTENDED_KEY_USAGES.TimeStamping
                    ]
                }),
            privateKeyPemData: certUtil.conversions.berToPem("PRIVATE KEY", await rawCert.exportPrivateKey(keyPair.privateKey))
        });
        return zkPkiCert;
    }

    // create ZkPki certificate from options
    this.createCertificate = async (issuerKeyPair, algorithm, keySizeOrCurveName, parameters = {}) => {
        validateCertificateParameters(parameters);
        const keyPair = await generateKeyPair(algorithm, keySizeOrCurveName);
        const zkPkiCert = this.loadCertificate({
            certificate: await rawCert.createRawCertificate(issuerKeyPair, keyPair.publicKey, parameters),
            privateKeyPemData: certUtil.conversions.berToPem("PRIVATE KEY", await rawCert.exportPrivateKey(keyPair.privateKey))
        });
        return zkPkiCert;
    }

    // create ZkPki certificate from CSR
    this.createCertificateFromCsr = async (issuerKeyPair, csrPemData) => {
        validateCertificateSigningRequest(csrPemData);

        // TODO: write this
    }
}

module.exports = new ZkPkiCertFactory();

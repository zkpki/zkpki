"use strict";

// initialization of crypto
const WebCryptoOpenSsl = require("node-webcrypto-ossl");
const pkijs = require("pkijs");
const asn1js = require("asn1js");
const crypto = new WebCryptoOpenSsl();
pkijs.setEngine("ZkPki", crypto, new pkijs.CryptoEngine({ name: "", crypto: crypto, subtle: crypto.subtle }));

const conversions = require("./conversions.js");
const constants = require("./constants.js");
const startingSerialNumber = 100000;

const ipAddress = require("ip-address");

const zkpkiFactory = require("./zkpkicertfactory.js");


// internal functions
function validateCertificateOptions(options) {
    if (!Number.isInteger(options.serialNumber))
        throw new Error("serialNumber option is required and must be an integer");
    if (!Number.isInteger(options.lifetimeDays))
        throw new Error("lifetimeDays option is required and must be an integer");
    if (!options.issuerDn)
        throw new Error("issuerDn option is required");
    if (!options.subjectDn)
        throw new Error("subjectDn option is required");
    if (options.subjectAlterativeNames) {
        if (!Array.isArray(options.subjectAlternativeNames))
            throw new Error("subjectAlternativeNames option must be an array");
        options.subjectAlternativeNames.forEach(sAN => {
            if (!("ip" in sAN || "dns" in sAN)) {
                throw new Error(
                    "subjectAlternativeNames option is an array of objects with a single property, "
                    + "where that property is either 'ip' or 'dns'");
            }
        });
    }
}

function getBasicConstraintsExtensionForCa(pathLength) {
    const basicConstraints = pathLength
        ? new pkijs.BasicConstraints({ cA: true, pathLenConstraint: pathLength })
        : new pkijs.BasicConstraints({ cA: true });
    return new pkijs.Extension({
        extnID: "2.5.29.19",
        critical: true,
        extnValue: basicConstraints.toSchema().toBER(false),
        parsedValue: basicConstraints // Parsed value for well-known extensions
    });
}

function getKeyUsagesExtension(keyUsages, markCritical = false) {
    const bitArray = keyUsages & constants.KEY_USAGES.DecipherOnly ? new ArrayBuffer(2) : new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);
    bitView[0] |= (keyUsages & 0xff); // mask to only 1st byte
    if (keyUsages & constants.KEY_USAGES.DecipherOnly) {
        bitView[1] |= (constants.KEY_USAGES.DecipherOnly >> 8); // handle 2nd byte
    }
    const keyUsage = new asn1js.BitString({ valueHex: bitArray });
    return new pkijs.Extension({
        extnID: "2.5.29.15",
        critical: markCritical,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage // Parsed value for well-known extensions
    });
}

function getExtendedKeyUsagesExtension(ekuOids, markCritical = false) {
    const extKeyUsage = new pkijs.ExtKeyUsage({
        keyPurposes: ekuOids
    });
    return new pkijs.Extension({
        extnID: "2.5.29.37",
        critical: markCritical,
        extnValue: extKeyUsage.toSchema().toBER(false),
        parsedValue: extKeyUsage // Parsed value for well-known extensions
    });
}

async function getSubjectKeyIdentifierExtension(subjectPublicKey) {
    const keyDer = await pkijs.getCrypto().exportKey("spki", subjectPublicKey);
    const thumbprint = await pkijs.getCrypto().digest({ name: "SHA-1" }, keyDer);
    return new pkijs.Extension({
        extnID: "2.5.29.14",
        critical: false,
        extnValue: (new asn1js.OctetString({ valueHex: thumbprint })).toBER(false)
    });
}

async function getAuthorityKeyIdentifierExtension(authorityPublicKey) {
    const keyDer = await pkijs.getCrypto().exportKey("spki", authorityPublicKey);
    const thumbprint = await pkijs.getCrypto().digest({ name: "SHA-1" }, keyDer);
    return new pkijs.Extension({
        extnID: "2.5.29.35",
        critical: false,
        extnValue: new pkijs.AuthorityKeyIdentifier({
            keyIdentifier: (new asn1js.OctetString({ valueHex: thumbprint }))
        }).toSchema().toBER(false)
    });
}

function parseIpAddress(ipAddressString) {
    const address4 = new ipAddress.Address4(ipAddressString);
    if (address4.isValid())
        return address4.toArray();
    const address6 = new ipAddress.Address6(ipAddressString);
    if (address6.isValid())
        return address6.toByteArray();
    throw new Error(`${ipAddressString} is not a valid IP address`);
}

function getSubjectAlternativeNamesExtension(subjectAlternativeNames) {
    const names = [];
    subjectAlternativeNames.forEach(sAN => {
        if ("ip" in sAN) {
            const ipAddress = parseIpAddress(sAN.ip);
            names.push(new pkijs.GeneralName({
                type: 7, // iPAddress
                value: new asn1js.OctetString({
                    valueHex: (new Uint8Array([ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]])).buffer
                })
            }));
        }
        if ("dns" in sAN) 
            names.push(new pkijs.GeneralName({
                type: 2, // dNSName
                value: sAN.dns
            }));
    });
    const altNames = new pkijs.GeneralNames({
        names: names
    });
    return new pkijs.Extension({
        extnID: "2.5.29.17",
        critical: false,
        extnValue: altNames.toSchema().toBER(false)
    });
}


// exports
exports.generateKeyPair = async (algorithmName, keySize) => {
    const algorithm = pkijs.getAlgorithmParameters(algorithmName, "generatekey");
    if (keySize)
        algorithm.algorithm.modulusLength = keySize;
    return await pkijs.getCrypto().generateKey(algorithm.algorithm, true, algorithm.usages);
}

exports.createCertificate = async (issuerKeyPair, subjectPublicKey, options = {}) => {
    validateCertificateOptions(options);

    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serialNumber });
    cert.issuer.typesAndValues = conversions.stringToDnTypesAndValues(options.issuerDn);
    cert.subject.typesAndValues = conversions.stringToDnTypesAndValues(options.subjectDn);
    [cert.notBefore.value, cert.notAfter.value] = conversions.getCertificateDateRange(options.lifetimeDays);

    // Basic Constraints
    cert.extensions = [];
    if (options.isCa)
        cert.extensions.push(getBasicConstraintsExtensionForCa(options.pathLength));

    // Key Usages and Extended Key Usages
    if (options.keyUsages)
        cert.extensions.push(getKeyUsagesExtension(options.keyUsages));
    if (options.extendedKeyUsages)
        cert.extensions.push(getExtendedKeyUsagesExtension(options.extendedKeyUsages));

    // Key Identifiers
    cert.extensions.push(await getSubjectKeyIdentifierExtension(subjectPublicKey));
    cert.extensions.push(await getAuthorityKeyIdentifierExtension(issuerKeyPair.publicKey));

     // Subject Alternative Names
    if (options.subjectAlternativeNames)
        cert.extensions.push(getSubjectAlternativeNamesExtension(options.subjectAlternativeNames));

    await cert.subjectPublicKeyInfo.importKey(subjectPublicKey);
    await cert.sign(issuerKeyPair.privateKey, "SHA-256");

    return zkpkiFactory.create({ certificate: cert });
}

exports.newRootCertificateAuthority = async (distinguishedName, lifetimeDays, algorithm, keySize) => {
    const keyPair = await exports.generateKeyPair(algorithm || constants.ALGORITHMS.RsaSsaPkcs1V1_5, keySize || 2048);
    const zkpkicert = await exports.createCertificate(keyPair,
        keyPair.publicKey,
        {
            serialNumber: startingSerialNumber,
            issuerDn: distinguishedName,
            subjectDn: distinguishedName,
            lifetimeDays: lifetimeDays || (365 * 10),
            isCa: true,
            keyUsages: constants.KEY_USAGES.KeySignCert | constants.KEY_USAGES.CrlSign,
            extendedKeyUsages: [
                constants.EXTENDED_KEY_USAGES.MsCertificateTrustListSigning,
                constants.EXTENDED_KEY_USAGES.ServerAuthentication,
                constants.EXTENDED_KEY_USAGES.ClientAuthentication,
                constants.EXTENDED_KEY_USAGES.OcspSigning,
                constants.EXTENDED_KEY_USAGES.TimeStamping
            ]
        });
    zkpkicert.privateKeyPemData =
        conversions.berToPem("PRIVATE KEY", await pkijs.getCrypto().exportKey("pkcs8", keyPair.privateKey));
    return zkpkicert;
}

exports.ALGORITHMS = constants.ALGORITHMS;
exports.KEY_USAGES = constants.KEY_USAGES;
exports.EXTENDED_KEY_USAGES = constants.EXTENDED_KEY_USAGES;

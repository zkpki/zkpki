"use strict";

// initialization of crypto
const { Crypto } = require("@peculiar/webcrypto");
const pkijs = require("pkijs");
const asn1js = require("asn1js");
const crypto = new Crypto();
pkijs.setEngine("ZkPki", crypto, new pkijs.CryptoEngine({ name: "", crypto: crypto, subtle: crypto.subtle }));

const ipAddress = require("ip-address");

const certUtil = require("../cert-util");

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
    const bitArray = keyUsages & certUtil.KEY_USAGES.DecipherOnly ? new ArrayBuffer(2) : new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);
    bitView[0] |= (keyUsages & 0xff); // mask to only 1st byte
    if (keyUsages & certUtil.KEY_USAGES.DecipherOnly) {
        bitView[1] |= (certUtil.KEY_USAGES.DecipherOnly >> 8); // handle 2nd byte
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


exports.generateRsaKeyPair = async (algorithmName, keySize) => {
    const algorithm = pkijs.getAlgorithmParameters(algorithmName, "generatekey");
    if (keySize)
        algorithm.algorithm.modulusLength = keySize;
    return await pkijs.getCrypto().generateKey(algorithm.algorithm, true, algorithm.usages);
}

exports.generateEcdsaKeyPair = async (curveName) => {
    const algorithm = pkijs.getAlgorithmParameters(certUtil.ALGORITHMS.Ecdsa, "generatekey");
    if (curveName)
        algorithm.algorithm.namedCurve = curveName;
    return await pkijs.getCrypto().generateKey(algorithm.algorithm, true, algorithm.usages);
}

exports.exportPrivateKey = async (keyPair) => {
    return await pkijs.getCrypto().exportKey("pkcs8", keyPair.privateKey);
}

exports.createRawCertificate = async (issuerKeyPair, subjectPublicKey, options = {}) => {
    const rawCert = new pkijs.Certificate();
    rawCert.version = 2;
    rawCert.serialNumber = new asn1js.Integer({ value: options.serialNumber });
    rawCert.issuer.typesAndValues = certUtil.conversions.dnStringToDnTypesAndValues(options.issuerDn);
    rawCert.subject.typesAndValues = certUtil.conversions.dnStringToDnTypesAndValues(options.subjectDn);
    [rawCert.notBefore.value, rawCert.notAfter.value] =
        certUtil.conversions.getCertificateDateRange(options.lifetimeDays);

    // Basic Constraints
    rawCert.extensions = [];
    if (options.isCa)
        rawCert.extensions.push(getBasicConstraintsExtensionForCa(options.pathLength));

    // Key Usages and Extended Key Usages
    if (options.keyUsages)
        rawCert.extensions.push(getKeyUsagesExtension(options.keyUsages));
    if (options.extendedKeyUsages)
        rawCert.extensions.push(getExtendedKeyUsagesExtension(options.extendedKeyUsages));

    // Key Identifiers
    rawCert.extensions.push(await getSubjectKeyIdentifierExtension(subjectPublicKey));
    rawCert.extensions.push(await getAuthorityKeyIdentifierExtension(issuerKeyPair.publicKey));

    // Subject Alternative Names
    if (options.subjectAlternativeNames)
        rawCert.extensions.push(getSubjectAlternativeNamesExtension(options.subjectAlternativeNames));

    await rawCert.subjectPublicKeyInfo.importKey(subjectPublicKey);
    await rawCert.sign(issuerKeyPair.privateKey, "SHA-256");

    return rawCert;
}

exports.parseRawCertificate = (certificateBuffer) => {
    const asn1 = asn1js.fromBER(certificateBuffer);
    if (asn1.result.error) {
        throw new Error(`Unable to parse raw certificate: ${asn1.result.error}`);
    }
    return new pkijs.Certificate({ schema: asn1.result });
}

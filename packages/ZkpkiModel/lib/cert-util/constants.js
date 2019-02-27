"use strict";

module.exports = Object.freeze({
    KEY_USAGES: {
        DigitalSignature: 1 << 7,
        NonRepudiation: 1 << 6,
        KeyEncipherment: 1 << 5,
        DataEncipherment: 1 << 4,
        KeyAgreement: 1 << 3,
        KeySignCert: 1 << 2,
        CrlSign: 1 << 1,
        EncipherOnly: 1 << 0,
        DecipherOnly: 1 << 15 // Adds a second Byte to ASN.1 buffer
    },
    EXTENDED_KEY_USAGES: {
        ServerAuthentication: "1.3.6.1.5.5.7.3.1",
        ClientAuthentication: "1.3.6.1.5.5.7.3.2",
        CodeSigning: "1.3.6.1.5.5.7.3.3",
        EmailProtection: "1.3.6.1.5.5.7.3.4",
        TimeStamping: "1.3.6.1.5.5.7.3.8",
        OcspSigning: "1.3.6.1.5.5.7.3.9",
        MsCertificateTrustListSigning: "1.3.6.1.4.1.311.10.3.1",
        MsEncryptedFileSystem: "1.3.6.1.4.1.311.10.3.4"
        // More found here:
        // https://docs.microsoft.com/en-us/windows/desktop/api/CertEnroll/nn-certenroll-ix509extensionenhancedkeyusage
        // If you add more, please add to conversions.js for text representation
    },
    ALGORITHMS: {
        RsaSsaPkcs1V1_5: "RSASSA-PKCS1-v1_5",
        RsaPss: "RSA-PSS",
        Ecdsa: "ECDSA"
    },
    ELLIPTIC_CURVE_NAMES: {
        NistP256: "P-256",
        NistP384: "P-384",
        NistP521: "P-521"
    }
});

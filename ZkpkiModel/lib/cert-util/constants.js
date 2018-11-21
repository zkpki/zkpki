'use strict';

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
        ServerAuthentication: 1,
        ClientAuthentication: 1 << 1,
        CodeSigning: 1 << 2,
        EmailProtection: 1 << 3,
        TimeStamping: 1 << 4,
        OcspSigning: 1 << 5,
        MsCertificateTrustListSigning: 1 << 6,
        MsEncryptedFileSystem: 1 << 7
    },
    ALGORITHMS: {
        RsaSsaPkcs1V1_5: "RSASSA-PKCS1-v1_5",
        RsaPss: "RSA-PSS",
        Ecdsa: "ECDSA"
    }
});

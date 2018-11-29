const assert = require("assert");
const certUtil = require("../../lib/cert-util");

describe("Certificate creation functions", function() {
    it("Create certificate basic",
        async function () {
            const keyPair = await certUtil.generateKeyPair(certUtil.ALGORITHMS.RsaPss, 4096);
            const cert = await certUtil.createCertificate(keyPair,
                keyPair.publicKey,
                {
                    serialNumber: 123,
                    issuerDn: "cn=foo",
                    subjectDn: "cn=foo",
                    lifetimeDays: 365 * 10,
                    isCa: true,
                    subjectAlternativeNames: [
                        { ip: "192.168.0.1" }, { dns: "hello.com" }
                    ],
                    keyUsages: certUtil.KEY_USAGES.KeySignCert |
                        certUtil.KEY_USAGES.CrlSign |
                        certUtil.KEY_USAGES.DigitalSignature |
                        certUtil.KEY_USAGES.KeyAgreement |
                        certUtil.KEY_USAGES.KeyEncipherment,
                    extendedKeyUsages: [
                        certUtil.EXTENDED_KEY_USAGES.ServerAuthentication,
                        certUtil.EXTENDED_KEY_USAGES.ClientAuthentication
                    ]
                });
            assert.ok(cert.serialNumber === 123, "Self-signed certificate serial number");
            assert.ok(cert.subject === "CN=foo", "Beautified subject distinguished name");
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            assert.ok(cert.issuedDate.getTime() === today.getTime(), "Issued today");
            const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            expire.setDate(expire.getDate() + (365 * 10));
            assert.ok(cert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
            assert.ok(cert.certificate, "Certificate PEM is not empty");
            assert.ok(cert.privateKey === null, "Private key PEM is empty");
            // TODO: parse certificate and check values directly
            // TODO: check that authority key identifier matches subject key identifier
        });

    it("Create new Root CA",
        async function() {
            const cert =
                await certUtil.newRootCa("cn=dan peterson,o=company,c=US",
                    365 * 5,
                    certUtil.ALGORITHMS.RsaSsaPkcs1V1_5,
                    2048);
            assert.ok(cert.serialNumber === 100000, "Root CA certificate serial number");
            assert.ok(cert.subject === "CN=dan peterson,O=company,C=US", "Beautified subject distinguished name");
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            assert.ok(cert.issuedDate.getTime() === today.getTime(), "Issued today");
            const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            expire.setDate(expire.getDate() + (365 * 5));
            assert.ok(cert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
            assert.ok(cert.certificate, "Certificate PEM is not empty");
            assert.ok(cert.privateKey, "Private key PEM is not empty");
            // TODO: parse certificate and check values directly
            // TODO: check that authority key identifier matches subject key identifier
        });
});

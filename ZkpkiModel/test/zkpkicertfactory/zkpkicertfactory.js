const assert = require("assert");
const zkpkiCertFactory = require("../../lib/zkpkicertfactory");

describe("Certificate creation functions", function () {
    it("Create certificate basic",
        async function () {
            const keyPair = await certUtil.generateKeyPair(certUtil.ALGORITHMS.RsaPss, 4096);
            const zkpkiCert = await zkpkiCertFactory.createCertificate(keyPair,
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
            assert.ok(zkpkiCert.serialNumber === 123, "Self-signed certificate serial number");
            assert.ok(zkpkiCert.subject === "CN=foo", "Beautified subject distinguished name");
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            assert.ok(zkpkiCert.issueDate.getTime() === today.getTime(), "Issued today");
            const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            expire.setDate(expire.getDate() + (365 * 10));
            assert.ok(zkpkiCert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
            assert.ok(zkpkiCert.certificatePemData, "Certificate PEM is not empty");
            assert.ok(zkpkiCert.privateKeyPemData === null, "Private key PEM is empty");
            // TODO: parse certificate and check values directly
            // TODO: check that authority key identifier matches subject key identifier
        });

    it("Create new Root CA",
        async function () {
            const cert =
                await certUtil.newRootCertificateAuthority("cn=dan peterson,o=company,c=US",
                    365 * 5,
                    certUtil.ALGORITHMS.RsaSsaPkcs1V1_5,
                    2048);
            assert.ok(cert.serialNumber === 100000, "Root CA certificate serial number");
            assert.ok(cert.subject === "CN=dan peterson,O=company,C=US", "Beautified subject distinguished name");
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            assert.ok(cert.issueDate.getTime() === today.getTime(), "Issued today");
            const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            expire.setDate(expire.getDate() + (365 * 5));
            assert.ok(cert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
            assert.ok(cert.certificatePemData, "Certificate PEM is not empty");
            assert.ok(cert.privateKeyPemData, "Private key PEM is not empty");
            // TODO: parse certificate and check values directly
            // TODO: check that authority key identifier matches subject key identifier
        });
});

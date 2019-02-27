const assert = require("assert").strict;
const certUtil = require("../../lib/cert-util");
const rawCert = require("../../lib/zkpkicertfactory/rawcert.js");
const zkPkiCertFactory = require("../../lib/zkpkicertfactory");

describe("ZKIPKI Certificate Factory",
    function () {
        // PEM file generated from OpenSSL
        const certPemString = `-----BEGIN CERTIFICATE-----
MIIFjDCCA3SgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCVVMx
DTALBgNVBAgMBFV0YWgxDjAMBgNVBAoMBUJMQUNLMQwwCgYDVQQLDANEZXYxFjAU
BgNVBAMMDWlzc3VpbmctYmxhY2swHhcNMTkwMjI2MjM1MjQ0WhcNMjEwMjI1MjM1
MjQ0WjBmMQswCQYDVQQGEwJVUzENMAsGA1UECAwEVXRhaDEXMBUGA1UEBwwOUGxl
YXNhbnQgR3JvdmUxDjAMBgNVBAoMBUJMQUNLMQwwCgYDVQQLDANEZXYxETAPBgNV
BAMMCHdpbGRjYXJkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnhWb
5nPcAss95+4stG8BiZC8sffH79ypzkjI4StcC0BCewiD5FtluBePpY8tMOOm+WBI
RxW3eGXBqy1rFRJRsSw4Dv/EKRQi05T0KRqf1Rfhwv+CXCTg6gt/5FD0asA4gcle
t6xfkkZYlcTozEG9BZcBurrdacHpJ9SB0qBnWF63h7MbJ81PsOImL49W6i5WiZQM
wsRSsR4eHYcfUsjrWYuxwucnSdm63Cm/p7ICaCQHvsuxDu7TuaYCSWaLHGQwaKy7
K0mp1rSelxWj7qiS4wu2Y4+5d+TrMmvOhZp0aXbGi7SuDBamQxltWyH9sK2+RPCQ
uFu7FPys2i0ypfwksQIDAQABo4IBVjCCAVIwHQYDVR0RBBYwFIIMKi5ibGFjay5j
b3JwhwQKBQU3MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMD4GCWCGSAGG
+EIBDQQxFi9HZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlIGZyb20gaXNzdWlu
Zy1ibGFjazAdBgNVHQ4EFgQUDpt34eiOO0oqs0D0VnfY3B4FNEIwgY4GA1UdIwSB
hjCBg4AUD6F3kYLCFeO0cV6JIIzuf9TuWaGhZ6RlMGMxCzAJBgNVBAYTAlVTMQ0w
CwYDVQQIDARVdGFoMRcwFQYDVQQHDA5QbGVhc2FudCBHcm92ZTEOMAwGA1UECgwF
QkxBQ0sxDDAKBgNVBAsMA0RldjEOMAwGA1UEAwwFYmxhY2uCAhAAMA4GA1UdDwEB
/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEA
iIoLymXzy0hvwIbrmsrNlB0YaRG++xbpo1qX3qVNSLl+pgS0KbAoX+iaZIettTv3
WgzXvsr93BHRvf6iUv/fxuTpqQWtNWBDsxEYOWEPSgC4YfbV8Mlk6PI/gHeSB3OS
QI0uR7qUW/JV2S7gbJdZjJovdt8AIEWz6ktOJm3SiU0g9f5aVMs9s3DrwwobeDHb
gw/4hIZpKUHtp9FcOyyC5ktF05ULf1oZMDjrC9D5f2TUqAGZ4rR15K2IcwQvYSgn
6tZaCXU9YJvhSX4aDuk9FatjX/L6i8lNQW9t+zUbXXbWVgC+3uatZfAP5kxO1s2T
S6xz6wDlyAjly0YEzzQaC18FRzUomhSCga2PeiqHsRHzrediV8LH5mnwfJM7tmpB
LqEZRF4QngM4MlMzaMPwNGfX2xrLxmroeg8d3DBiDc5ofQfpqGkTM010wgDDIeEK
UmioeH70PnXqwVLdCaEeEFMeUn9relSTwJrAJ8SsITC/Zkrv4kUI8eeywn7tWprn
2ycqNw2H8D0oduyuHx+egDV6cX4EHEwZWdCMPeQ/Wru1crFJ2iAiREabHuBiUZlT
7kDiNzZWtXitb6ZxjFyaQKW2Hjuk1RiCecYgGeBH6ib8CmRvqUwN3r4CNljbROd+
pPb5vOaOmWSqcTdsUEUVCDP8sTqu5yUXLODxbn4jfJs=
-----END CERTIFICATE-----`;


        it("Load Certificate From PEM",
            async function () {
                const zkPkiCert = await zkPkiCertFactory.loadCertificate({ certificatePemData: certPemString });
                assert.deepEqual(zkPkiCert.serialNumber, "1000");
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.deepEqual(zkPkiCert.publicKeySize, 2048);
                assert.deepEqual(zkPkiCert.issuer, "CN=issuing-black,OU=Dev,O=BLACK,S=Utah,C=US");
                assert.deepEqual(zkPkiCert.subject, "CN=wildcard,OU=Dev,O=BLACK,L=Pleasant Grove,S=Utah,C=US");
                const issueDate = new Date(Date.parse("2019-02-26T16:52:44-07:00"));
                assert.ok(zkPkiCert.issueDate.getTime() === issueDate.getTime());
                const expirationDate = new Date(Date.parse("2021-02-25T16:52:44-07:00"));
                assert.ok(zkPkiCert.expirationDate.getTime() === expirationDate.getTime());
                assert.ok(zkPkiCert.keyUsages.includes("DigitalSignature"));
                assert.ok(zkPkiCert.keyUsages.includes("KeyEncipherment"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ServerAuthentication"));
                assert.ok(zkPkiCert.keyUsagesCritical === true);
                assert.ok(zkPkiCert.extendedKeyUsagesCritical === false);
                assert.ok(zkPkiCert.isCa === false);
                assert.deepEqual(zkPkiCert.certificatePemData, certPemString);
                assert.ok(zkPkiCert.certificate !== null);
                assert.ok(zkPkiCert.privateKeyPemData === null);
                assert.ok(zkPkiCert.privateKey === null);
            });

        it("Load Certificate From Raw",
            async function() {
                const rsaSsa4096 = await rawCert.generateRsaKeyPair(certUtil.ALGORITHMS.RsaSsaPkcs1V1_5, 4096);
                const serialNumber = 3456;
                const raw = await rawCert.createRawCertificate(rsaSsa4096,
                    rsaSsa4096.publicKey,
                    {
                        serialNumber: serialNumber,
                        issuerDn: "CN=dan test,C=US",
                        subjectDn: "CN=dan test,C=US",
                        lifetimeDays: 100,
                        keyUsages: certUtil.KEY_USAGES.KeySignCert | certUtil.KEY_USAGES.KeyAgreement | certUtil.KEY_USAGES.DigitalSignature,
                        extendedKeyUsages: [
                            certUtil.EXTENDED_KEY_USAGES.MsCertificateTrustListSigning,
                            certUtil.EXTENDED_KEY_USAGES.ServerAuthentication,
                            certUtil.EXTENDED_KEY_USAGES.ClientAuthentication
                        ]
                    });
                const zkPkiCert = await zkPkiCertFactory.loadCertificate({
                    certificate: raw,
                    privateKey: rsaSsa4096.privateKey
                });
                assert.ok(zkPkiCert.certificatePemData !== null);
                assert.ok(zkPkiCert.certificate !== null);
                assert.ok(zkPkiCert.privateKeyPemData !== null);
                assert.ok(zkPkiCert.privateKey !== null);
                assert.deepEqual(zkPkiCert.serialNumber, serialNumber.toString(16));
                assert.deepEqual(zkPkiCert.issuer, "CN=dan test,C=US");
                assert.deepEqual(zkPkiCert.subject, "CN=dan test,C=US");
                assert.ok(zkPkiCert.keyUsages.includes("KeySignCert"));
                assert.ok(zkPkiCert.keyUsages.includes("KeyAgreement"));
                assert.ok(zkPkiCert.keyUsages.includes("DigitalSignature"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("MsCertificateTrustListSigning"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ServerAuthentication"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ClientAuthentication"));
            });

        it("Create Certificate Authority",
            async function () {
                const zkPkiCert = await zkPkiCertFactory.createCertificateAuthority("cn=dan peterson,o=company,c=US",
                    365 * 5,
                    certUtil.ALGORITHMS.RsaSsaPkcs1V1_5,
                    2048);
                const serialNumber = 100000;
                assert.ok(zkPkiCert.serialNumber === serialNumber.toString(16), "Root CA certificate serial number");
                assert.ok(zkPkiCert.subject === "CN=dan peterson,O=company,C=US", "Beautified subject distinguished name");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkPkiCert.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + (365 * 5));
                assert.ok(zkPkiCert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
                assert.ok(zkPkiCert.certificatePemData, "Certificate PEM is not empty");
                assert.ok(zkPkiCert.privateKeyPemData, "Private key PEM is not empty");
                assert.ok(zkPkiCert.isCa);
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.deepEqual(zkPkiCert.publicKeySize, 2048);
                assert.ok(zkPkiCert.keyUsages.includes("KeySignCert"));
                assert.ok(zkPkiCert.keyUsages.includes("CrlSign"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("MsCertificateTrustListSigning"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ServerAuthentication"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ClientAuthentication"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("OcspSigning"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("TimeStamping"));
            });

        it("Create Certificate",
            async function () {
                const rawCert = require("../../lib/zkpkicertfactory/rawcert.js");
                const keyPair = await rawCert.generateRsaKeyPair(certUtil.ALGORITHMS.RsaPss, 4096);
                var serialNumber = 123;
                const zkPkiCert = await zkPkiCertFactory.createCertificate(keyPair,
                    certUtil.ALGORITHMS.RsaPss, 4096,
                    {
                        serialNumber: serialNumber,
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
                assert.ok(zkPkiCert.serialNumber === serialNumber.toString(16), "Self-signed certificate serial number");
                assert.ok(zkPkiCert.subject === "CN=foo", "Beautified subject distinguished name");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkPkiCert.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + (365 * 10));
                assert.ok(zkPkiCert.expirationDate.getTime() === expire.getTime(), "Expires in 5 years");
                assert.ok(zkPkiCert.certificatePemData, "Certificate PEM is not empty");
                assert.ok(zkPkiCert.privateKeyPemData, "Private key PEM is not empty");
                assert.ok(zkPkiCert.certificate, "Raw certificate is not empty");
                assert.ok(zkPkiCert.privateKey, "Raw private key is not empty");
                assert.ok(zkPkiCert.isCa, "Is CA");
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, certUtil.ALGORITHMS.RsaPss);
                assert.deepEqual(zkPkiCert.publicKeySize, 4096);
                assert.ok(zkPkiCert.keyUsages.includes("KeySignCert"));
                assert.ok(zkPkiCert.keyUsages.includes("CrlSign"));
                assert.ok(zkPkiCert.keyUsages.includes("DigitalSignature"));
                assert.ok(zkPkiCert.keyUsages.includes("KeyAgreement"));
                assert.ok(zkPkiCert.keyUsages.includes("KeyEncipherment"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ServerAuthentication"));
                assert.ok(zkPkiCert.extendedKeyUsages.includes("ClientAuthentication"));
                // TODO: check subject alternative names
            });

        it("Create Certificate From CSR",
            async function () {
                assert.ok(false); // TODO:
            });
    });

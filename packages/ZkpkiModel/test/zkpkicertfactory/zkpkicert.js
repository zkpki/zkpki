const assert = require("assert").strict;
const ZkPkiCert = require("../../lib/zkpkicertfactory/zkpkicert.js");
const rawCert = require("../../lib/zkpkicertfactory/rawcert.js");
const certUtil = require("../../lib/cert-util");

describe("ZKPKI Certificate Object",
    function () {
        // PEM file generated from Microsoft Certificate Services CA
        const certPemString = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;
        const cert2PrivateKeyPemString = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHihwSfTUvXSyQ
P0LT4BePxe7iVpgqDN0lajPWfb9QJpsxAFC2jxQI55BKmejiDJ/knDgVWLqf5Mrj
Lo+tLedMDgUou9HsOnJKuU+fV1n8kD7vWCN6e0kUjyeLiswpflx6xyXIg+IZQO2/
itInPc9JZhnwiQXFwp8gPQL8q5/DfUc85cf+twD/GrL8u++I7FF1U0T6RS6oytLx
U18kxVWRAqKJ7/Yr7njQ/Pe/b6TPGaQnO0kSOuN8+p0P/2lYYYfBtsUtwrzwtaIQ
IAO6sTQNblzGZrELFBc11NrG8unNvBzjlLde6c74dAGQr05t6F83bxtSz5w8pkmk
WufiWLxbAgMBAAECggEBALO7E/QXcYt7GoPHZ5NeuvpWqAiZRTBDLALieVTPKT6x
t4HYrdryX3Jx2cdIgLrz8iXCDMY1iMwzEgi1zNaJjVg1HLKHEtv7/SyPZEe7L6PN
7dI6iqJtX/MzysPnPmR1nCk/LipBmKt0j3HDQe30v7x2ShEd6uQpnJk2O3WJxTsY
CdT1n46hWoBHwa6YUErt3MVTUubrKs7Pj4jRkijCCQUleOLvLPnJ6iHQyJ9FCyHT
/7F2TBC4SHWhrnsM0mLw6MnpTvmcwClFE59kfVrrMU9rKmiy64ODDA8AgNnm0vdj
xo/njG8Hu7cKhAO+YziBQzDhP+fEy21bg0fM398Dx2ECgYEA8L79Iz9UzH+BzzBp
eLWEzkqNyI67npgQPN6CfcSWQNU1JUF0mkVfrRpWq731UOI+ZpzDzjXDZW/MSVfg
aojaBPhAYnwUYqo/ylpH1b90CNLIKO3XIdDzfEmVFSVeiLIzevPs7UXHQmYxrX1a
NjasLwe/v6A6XSFIRpS3NyJXuCsCgYEA1C67SKFr9S8jIZGRh2z3ZHvsfCnEP4u8
5WzEdLAUAyJsoQLwLnguM0nEsOLOR8UeXbDzX3mO25cZvppRY+ro9k8SUQoo4gOV
Paa1eEACDeN+DvMpI3vuGg2Zqw3Yypnus5IRoSyuBMS2GLR04f6R05IsicDZA+11
ikc2rzg6RJECgYBQUdgQr2tyQsQjROqbbCwfyz3cgMpV0jPwqufsX+8lODzf7iOh
6K1QCm6KI/k5gBIDmB+3p7ZGHHOSsK/du0TJza1lbjI67MQVleNLi/GBlBlVlmxl
CtqBR+dmQ65zesi0J7ePPe2J2KCQWjcDyV/O3Q37N9DhC16atbkeuuV7OwKBgCWs
Nmxq3LQnrmEja2dUHYilyBMzhziRIvTJHwhoyuTTk93ym5pklC9fBaEyY9WyVfXk
mRF2j7rFVTjWRWUsLDivSV1CJIgcgr7zfnzfQH4eyh71ZXR7aIcPqx0H1FoEgrE3
WhH30N3f30T7pVUK0fFynp3Gs8FSw+/NPRRXM2FBAoGBAKCnEbIGgmlcq0C95uTr
eBgWiAzm5CRcCLidMa3gSKGde6gPBZVmTeAiWGZXboFjatfo8YUevbmiN/C6vQzS
hD5rEeXSAOS4+WqdaOHI8vMD5523436jb/ehyVzLmJnZXxO0qTDfTK08ZGZdFd1g
QmtblochXATMdn1BLoowtLgz
-----END PRIVATE KEY-----`;
        const cert2PemString = `-----BEGIN CERTIFICATE-----
MIIFFTCCAv2gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMx
DTALBgNVBAgMBFV0YWgxGTAXBgNVBAoMEE9uZSBJZGVudGl0eSBMTEMxDDAKBgNV
BAsMA1BBTTEXMBUGA1UEAwwOaXNzdWluZy1CbHVlQ0EwHhcNMTgwOTEyMDIzNDM3
WhcNMjAwOTExMDIzNDM3WjBpMQswCQYDVQQGEwJVUzENMAsGA1UECAwEVXRhaDEP
MA0GA1UEBwwGTGluZG9uMRkwFwYDVQQKDBBPbmUgSWRlbnRpdHkgTExDMQwwCgYD
VQQLDANQQU0xETAPBgNVBAMMCEJsdWVVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAx4ocEn01L10skD9C0+AXj8Xu4laYKgzdJWoz1n2/UCabMQBQ
to8UCOeQSpno4gyf5Jw4FVi6n+TK4y6PrS3nTA4FKLvR7DpySrlPn1dZ/JA+71gj
entJFI8ni4rMKX5cesclyIPiGUDtv4rSJz3PSWYZ8IkFxcKfID0C/Kufw31HPOXH
/rcA/xqy/LvviOxRdVNE+kUuqMrS8VNfJMVVkQKiie/2K+540Pz3v2+kzxmkJztJ
EjrjfPqdD/9pWGGHwbbFLcK88LWiECADurE0DW5cxmaxCxQXNdTaxvLpzbwc45S3
XunO+HQBkK9ObehfN28bUs+cPKZJpFrn4li8WwIDAQABo4HRMIHOMAkGA1UdEwQC
MAAwEQYJYIZIAYb4QgEBBAQDAgWgMD8GCWCGSAGG+EIBDQQyFjBHZW5lcmF0ZWQg
Q2xpZW50IENlcnRpZmljYXRlIGZyb20gaXNzdWluZy1CbHVlQ0EwHQYDVR0OBBYE
FKQrgXUQABNF3y2II6RTlSejGuzMMB8GA1UdIwQYMBaAFH62ypnwC6x+9fo+b6CU
U4hL8pgFMA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwQwDQYJKoZIhvcNAQELBQADggIBAC1UhgOm5itSvs/Vd5CG8VPTsoxqNtCx
eNSYiq/LrPwZYXO/w1RWpWYp/xe7QpNB4szELmlJtxTPqA4KQiTg+v5QDks26+Oe
WPpR+qTcxtJjVz/h+N035KP5D0cTYs1Mw6ZvaWBgsWiOAPxIo6dXktv24r8Rxgt2
8R8s8SR9o89nZsBsv0N/XafZvTyQdopDRkAOO80q6tdCntVvTHfjjuLixSLMm4jc
srdouL+Zwem2BqGU4lk5aEPkz1xvm76PwsyDlityYuVFqENLegGhS+w4evmkYvO/
tJ9SbysI35XGMyckqgwyUZf1dNzlp2Qvklh7FNtYdxZjuKtR/hySbSL7lquV3//j
SeuXVb3T7YOt7TBnHgBKzg7Uloa3OpCan3rfAANCCiGIazBUU9VaqrP95hoH3wI8
b4XwFWRmhzIKr7rjSqFXBYcNxNU07Y8/rTK8ausBrD44WhxpaXtEGC++a8v7kp08
NvAEt8UwQBEzN0dfh6T2KBCT26hbHOtmdgFMqjKTy62el7ZDtbNyr73doBCQNL1G
m/KQtiYxDwssGrHD/KerXRNYeYetuWs8LR5x2VKTOH443sulSKG9iJS+NHtiSiAe
8l4Zpkzxqy231xdL8PePrwvAVTUDyh91QFCAnxW+ifsb9xn/JKmM9vL5+SFq2eTh
z2yaUBhvyrus
-----END CERTIFICATE-----`;

        it("Constructor -- Null",
            async function () {
                const zkPkiCertNull = new ZkPkiCert();
                const zkPkiCertEmpty = new ZkPkiCert({});
                // r/w properties
                assert.ok(zkPkiCertNull.certificatePemData === null);
                assert.ok(zkPkiCertEmpty.certificatePemData === null);
                assert.ok(zkPkiCertNull.certificate === null);
                assert.ok(zkPkiCertEmpty.certificate === null);
                assert.ok(zkPkiCertNull.privateKeyPemData === null);
                assert.ok(zkPkiCertEmpty.privateKeyPemData === null);
                // r/o properties
                assert.throws(() => zkPkiCertNull.serialNumber, Error);
                assert.throws(() => zkPkiCertNull.subject, Error);
                assert.throws(() => zkPkiCertNull.issuer, Error);
                assert.throws(() => zkPkiCertNull.issueDate, Error);
                assert.throws(() => zkPkiCertNull.expirationDate, Error);
                assert.throws(() => zkPkiCertEmpty.serialNumber, Error);
                assert.throws(() => zkPkiCertEmpty.subject, Error);
                assert.throws(() => zkPkiCertEmpty.issuer, Error);
                assert.throws(() => zkPkiCertEmpty.issueDate, Error);
                assert.throws(() => zkPkiCertEmpty.expirationDate, Error);
                assert.throws(() => zkPkiCertEmpty.publicKeyAlgorithm, Error);
                assert.throws(() => zkPkiCertEmpty.publicKeySize, Error);
                assert.throws(() => zkPkiCertEmpty.ellipticCurveName, Error);
            });

        it("Constructor -- Raw Certificate",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.ok(zkPkiCert.certificatePemData === null);
                assert.ok(zkPkiCert.certificate !== null);
                assert.ok(zkPkiCert.privateKeyPemData === null);
                assert.ok(zkPkiCert.privateKey === null);
            });

        it("Constructor -- PEM Data (Cert Only)",
            async function () {
                const zkPkiCert = new ZkPkiCert({ certificatePemData: certPemString });
                assert.ok(zkPkiCert.certificatePemData !== null);
                assert.ok(zkPkiCert.certificate === null);
                assert.ok(zkPkiCert.privateKeyPemData === null);
                assert.ok(zkPkiCert.privateKey === null);
                assert.deepEqual(zkPkiCert.certificatePemData, certPemString);
            });

        it("Constructor -- PEM Data (Cert and Private Key)",
            async function () {
                const zkPkiCert = new ZkPkiCert({
                    certificatePemData: cert2PemString,
                    privateKeyPemData: cert2PrivateKeyPemString
                });
                assert.ok(zkPkiCert.certificatePemData !== null);
                assert.ok(zkPkiCert.certificate === null);
                assert.ok(zkPkiCert.privateKeyPemData !== null);
                assert.ok(zkPkiCert.privateKey === null);
                assert.deepEqual(zkPkiCert.certificatePemData, cert2PemString);
                assert.deepEqual(zkPkiCert.privateKeyPemData, cert2PrivateKeyPemString);
            });

        it("Serial Number Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.deepEqual(zkPkiCert.serialNumber, "7c000000028f702488e6979673000000000002");
            });

        it("Subject Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.deepEqual(zkPkiCert.subject, "CN=IssuingCA-CA1,O=DAN,C=US");
            });

        it("Issuer Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.deepEqual(zkPkiCert.issuer, "CN=DAN Root CA,O=DAN,C=US");
            });

        it("Issue Date Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                const issueDate = new Date(2016, 4, 23, 13, 7, 19, 0); // May 23, 2016 -- 13:07:19 MDT
                assert.deepEqual(zkPkiCert.issueDate, issueDate);
            });

        it("Expiration Date Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                const expirationDate = new Date(2026, 4, 23, 13, 17, 19, 0); // May 23, 2026 -- 13:17:19 MDT
                assert.deepEqual(zkPkiCert.expirationDate, expirationDate);
            });

        it("Public Key Algorithm Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
            });

        it("Public Key Size Property",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.deepEqual(zkPkiCert.publicKeySize, 4096);
            });

        it("Certificate and Private Key",
            async function() {
                const certData = certUtil.conversions.pemToBer(cert2PemString);
                const privateKeyData = certUtil.conversions.pemToBer(cert2PrivateKeyPemString);
                const rawC = rawCert.parseRawCertificate(certData);
                const rawK = rawCert.parseRawPrivateKey(privateKeyData);
                const zkPkiCert = new ZkPkiCert({
                    certificate: rawC,
                    privateKey: rawK
                });
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
                const privateKey = await zkPkiCert.getCryptoPrivateKey();
                assert.deepEqual(zkPkiCert.publicKeyAlgorithm, privateKey.algorithm.name);
                assert.deepEqual(zkPkiCert.publicKeySize, privateKey.algorithm.modulusLength);
            });
    });

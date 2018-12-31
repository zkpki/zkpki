const assert = require("assert").strict;
const ZkPkiCert = require("../../lib/zkpkicertfactory/zkpkicert.js");
const rawCert = require("../../lib/zkpkicertfactory/rawcert.js");
const certUtil = require("../../lib/cert-util");

describe("ZKPKI Certificate Object",
    function () {
        const certPemString = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

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
                // TODO: add key size and algorithm
            });

        it("Constructor -- Raw Certificate",
            async function () {
                const data = certUtil.conversions.pemToBer(certPemString);
                const raw = rawCert.parseRawCertificate(data);
                const zkPkiCert = new ZkPkiCert({ certificate: raw });
                assert.ok(zkPkiCert.certificatePemData === null);
                assert.ok(zkPkiCert.certificate !== null);
                assert.ok(zkPkiCert.privateKeyPemData === null);
            });

        it("Constructor -- PEM Data (Cert Only)",
            async function () {
                const zkPkiCert = new ZkPkiCert({ certificatePemData: certPemString });
                assert.ok(zkPkiCert.certificatePemData !== null);
                assert.ok(zkPkiCert.certificate === null);
                assert.ok(zkPkiCert.privateKeyPemData === null);
                assert.deepEqual(zkPkiCert.certificatePemData, certPemString);
            });

        it("Constructor -- PEM Data (Cert and Private Key)",
            async function() {
                assert.ok(false); // TODO:
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
                assert.ok(false); // TODO:
            });

        it("Expiration Date Property",
            async function () {
                assert.ok(false); // TODO:
            });
    });

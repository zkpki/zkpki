const assert = require("assert").strict;;
const zkpkiModel = require("../index.js");

describe("ZKPKI Model",
    function() {
        it("Initialize RSA 2048",
            async function() {
                await zkpkiModel.initialize("CN=Root CA,O=zkpki,C=US", zkpkiModel.ALGORITHMS.RsaSsaPkcs1V1_5, 2048);
                assert.ok(zkpkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkpkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkpkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkpkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkpkiModel.rootCa.subject, "CN=Root CA,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkpkiModel.rootCa.issuer, "CN=Root CA,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkpkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkpkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.ok(zkpkiModel.rootCa.publicKeyAlgorithm, zkpkiModel.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.ok(zkpkiModel.rootCa.publicKeySize, 2048);
                assert.ok(zkpkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("Initialize RSA PSS 4096",
            async function() {
                await zkpkiModel.initialize("CN=Another CA,OU=blah,O=zkpki,C=US", zkpkiModel.ALGORITHMS.RsaPss, 4096);
                assert.ok(zkpkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkpkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkpkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkpkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkpkiModel.rootCa.subject, "CN=Another CA,OU=blah,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkpkiModel.rootCa.issuer, "CN=Another CA,OU=blah,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkpkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkpkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.ok(zkpkiModel.rootCa.publicKeyAlgorithm, zkpkiModel.ALGORITHMS.RsaPss);
                assert.ok(zkpkiModel.rootCa.publicKeySize, 4096);
                assert.ok(zkpkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("Initialize ECDSA P-521",
            async function () {
                await zkpkiModel.initialize("CN=ECDSA CA,OU=blah,O=zkpki,C=US",
                    zkpkiModel.ALGORITHMS.Ecdsa, zkpkiModel.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(zkpkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkpkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkpkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkpkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkpkiModel.rootCa.subject, "CN=ECDSA CA,OU=blah,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkpkiModel.rootCa.issuer, "CN=ECDSA CA,OU=blah,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkpkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkpkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.ok(zkpkiModel.rootCa.publicKeyAlgorithm, zkpkiModel.ALGORITHMS.Ecdsa);
                assert.ok(zkpkiModel.rootCa.ellipticCurveName, zkpkiModel.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(zkpkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("serialize",
            async function() {
                assert.ok(false); // TODO:
            });

        it("deserialize",
            async function () {
                assert.ok(false); // TODO:
            });

        it("issueCertificate",
            async function () {
                assert.ok(false); // TODO:
            });

        it("issueCertificateForCsr",
            async function () {
                assert.ok(false); // TODO:
            });
    });

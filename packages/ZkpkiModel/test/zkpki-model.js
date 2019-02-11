const assert = require("assert").strict;;
const zkPkiModel = require("../index.js");

describe("ZKPKI Model",
    function() {
        it("Initialize RSA 2048",
            async function() {
                await zkPkiModel.initialize("CN=Root CA,O=zkpki,C=US", zkPkiModel.ALGORITHMS.RsaSsaPkcs1V1_5, 2048);
                assert.ok(zkPkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkPkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkPkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkPkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkPkiModel.rootCa.subject, "CN=Root CA,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkPkiModel.rootCa.issuer, "CN=Root CA,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkPkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkPkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.deepEqual(zkPkiModel.rootCa.publicKeyAlgorithm, zkPkiModel.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.deepEqual(zkPkiModel.rootCa.publicKeySize, 2048);
                assert.ok(zkPkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("Initialize RSA PSS 4096",
            async function() {
                await zkPkiModel.initialize("CN=Another CA,OU=blah,O=zkpki,C=US", zkPkiModel.ALGORITHMS.RsaPss, 4096);
                assert.ok(zkPkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkPkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkPkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkPkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkPkiModel.rootCa.subject, "CN=Another CA,OU=blah,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkPkiModel.rootCa.issuer, "CN=Another CA,OU=blah,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkPkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkPkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.deepEqual(zkPkiModel.rootCa.publicKeyAlgorithm, zkPkiModel.ALGORITHMS.RsaPss);
                assert.deepEqual(zkPkiModel.rootCa.publicKeySize, 4096);
                assert.ok(zkPkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("Initialize ECDSA P-521",
            async function () {
                await zkPkiModel.initialize("CN=ECDSA CA,OU=blah,O=zkpki,C=US",
                    zkPkiModel.ALGORITHMS.Ecdsa, zkPkiModel.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(zkPkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkPkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkPkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkPkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                assert.deepEqual(zkPkiModel.rootCa.subject, "CN=ECDSA CA,OU=blah,O=zkpki,C=US", "Subject");
                assert.deepEqual(zkPkiModel.rootCa.issuer, "CN=ECDSA CA,OU=blah,O=zkpki,C=US", "Issuer");
                const now = new Date();
                const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                assert.ok(zkPkiModel.rootCa.issueDate.getTime() === today.getTime(), "Issued today");
                const expire = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                expire.setDate(expire.getDate() + 3652);
                assert.ok(zkPkiModel.rootCa.expirationDate.getTime() === expire.getTime(), "Expires in 3652 days");
                assert.deepEqual(zkPkiModel.rootCa.publicKeyAlgorithm, zkPkiModel.ALGORITHMS.Ecdsa);
                assert.deepEqual(zkPkiModel.rootCa.ellipticCurveName, zkPkiModel.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(zkPkiModel.certificates.length === 0, "Empty Certificate List");
            });

        it("Serialize Newly Initialized",
            async function() {
                await zkPkiModel.initialize("CN=Another CA,OU=blah,O=zkpki,C=US", zkPkiModel.ALGORITHMS.RsaPss, 4096);
                const data = await zkPkiModel.serialize();
                assert.ok(data !== null);
                const obj = JSON.parse(data);
                assert.ok(obj !== null);
                assert.deepEqual(obj.certificates, []);
                assert.deepEqual(obj.rootCa.certificatePemData, zkPkiModel.rootCa.certificatePemData);
                assert.deepEqual(obj.rootCa.privateKeyPemData, zkPkiModel.rootCa.privateKeyPemData);
                assert.ok(obj.settings === null);
            });

        const serializedRootCa = `{"rootCa":{"certificatePemData":"-----BEGIN CERTIFICATE-----\\r\\n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\\r\\n-----END CERTIFICATE-----","privateKeyPemData":"-----BEGIN PRIVATE KEY-----\\r\\n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\\r\\nElz+aMLVUlSneh/f+Vdhe6qTG/CC\\r\\n-----END PRIVATE KEY-----"},"settings":null,"certificates":[]}`;

        it("Deserialize Just Root CA",
            async function () {
                await zkPkiModel.deserialize(serializedRootCa);
                assert.ok(zkPkiModel.rootCa.certificate !== null);
                assert.deepEqual(zkPkiModel.rootCa.subject, "CN=Another CA,OU=blah,O=zkpki,C=US");
                assert.deepEqual(zkPkiModel.rootCa.publicKeyAlgorithm, zkPkiModel.ALGORITHMS.RsaPss);
                assert.deepEqual(zkPkiModel.rootCa.publicKeySize, 4096);
                assert.deepEqual(zkPkiModel.rootCa.certificatePemData, "-----BEGIN CERTIFICATE-----\r\n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\r\n-----END CERTIFICATE-----");
                assert.deepEqual(zkPkiModel.rootCa.privateKeyPemData, "-----BEGIN PRIVATE KEY-----\r\n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\r\nElz+aMLVUlSneh/f+Vdhe6qTG/CC\r\n-----END PRIVATE KEY-----");
                assert.deepEqual(zkPkiModel.certificates, []);
                assert.ok(zkPkiModel.settings === null);
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

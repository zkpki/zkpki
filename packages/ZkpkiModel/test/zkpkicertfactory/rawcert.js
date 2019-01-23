const assert = require("assert").strict;
const certUtil = require("../../lib/cert-util");
const rawCert = require("../../lib/zkpkicertfactory/rawcert.js");

describe("Raw Certificate Functions",
    function() {
        it("Generate Key Pair",
            async function () {
                const rsaSsa2048 = await rawCert.generateRsaKeyPair(certUtil.ALGORITHMS.RsaSsaPkcs1V1_5, 2048);
                assert.deepEqual(rsaSsa2048.publicKey.algorithm.name, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.deepEqual(rsaSsa2048.publicKey.algorithm.modulusLength, 2048);
                assert.deepEqual(rsaSsa2048.publicKey.algorithm.hash.name, "SHA-256");
                assert.ok(rsaSsa2048.publicKey.extractable);
                assert.deepEqual(rsaSsa2048.privateKey.algorithm.name, certUtil.ALGORITHMS.RsaSsaPkcs1V1_5);
                assert.deepEqual(rsaSsa2048.privateKey.algorithm.modulusLength, 2048);
                assert.deepEqual(rsaSsa2048.privateKey.algorithm.hash.name, "SHA-256");
                assert.ok(rsaSsa2048.privateKey.extractable);

                const rsaPss4096 = await rawCert.generateRsaKeyPair(certUtil.ALGORITHMS.RsaPss, 4096);
                assert.deepEqual(rsaPss4096.publicKey.algorithm.name, certUtil.ALGORITHMS.RsaPss);
                assert.deepEqual(rsaPss4096.publicKey.algorithm.modulusLength, 4096);
                assert.deepEqual(rsaPss4096.publicKey.algorithm.hash.name, "SHA-256");
                assert.ok(rsaPss4096.publicKey.extractable);
                assert.deepEqual(rsaPss4096.privateKey.algorithm.name, certUtil.ALGORITHMS.RsaPss);
                assert.deepEqual(rsaPss4096.privateKey.algorithm.modulusLength, 4096);
                assert.deepEqual(rsaPss4096.privateKey.algorithm.hash.name, "SHA-256");
                assert.ok(rsaPss4096.privateKey.extractable);

                const ecdsaP521 = await rawCert.generateEcdsaKeyPair(certUtil.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.deepEqual(ecdsaP521.publicKey.algorithm.name, certUtil.ALGORITHMS.Ecdsa);
                assert.deepEqual(ecdsaP521.publicKey.algorithm.namedCurve, certUtil.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(ecdsaP521.publicKey.extractable);
                assert.deepEqual(ecdsaP521.privateKey.algorithm.name, certUtil.ALGORITHMS.Ecdsa);
                assert.deepEqual(ecdsaP521.privateKey.algorithm.namedCurve, certUtil.ELLIPTIC_CURVE_NAMES.NistP521);
                assert.ok(ecdsaP521.privateKey.extractable);
            });

        it("Export Private Key",
            async function () {
                assert.ok(false); // TODO:
            });

        it("Create Raw Certificate",
            async function () {
                assert.ok(false); // TODO:
            });

        it("Parse Raw Certificate",
            async function () {
                assert.ok(false); // TODO:
            });
    });

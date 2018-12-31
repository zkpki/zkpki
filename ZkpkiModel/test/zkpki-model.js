const assert = require("assert").strict;;
const zkpkiModel = require("../index.js");

describe("ZKPKI Model",
    function() {
        it("Initialize",
            function () {
                zkpkiModel.initialize("CN=Root CA,O=zkpki,C=US", zkpkiModel.certUtil.ALGORITHMS.RsaSsaPkcs1V1_5, 2048);
                assert.ok(zkpkiModel.rootCa !== null, "Created Root CA");
                assert.ok(zkpkiModel.rootCa.certificatePemData !== null, "Has Certificate PEM Data");
                assert.ok(zkpkiModel.rootCa.privateKeyPemData !== null, "Has Private Key PEM Data");
                assert.ok(zkpkiModel.rootCa.certificate !== null, "Has Raw Certificate");
                // TODO: assert issued today
                // TODO: assert subject and issuer
                // TODO: assert expiration is in 3652 days
                assert.ok(zkpkiModel.certificates.length === 0, "Empty Certificate List");
            });
    });

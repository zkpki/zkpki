const assert = require("assert");
const certUtil = require("../../lib/cert-util");

describe("Cert Util Conversions",
    function() {
        it("Beautify DN String",
            async function() {
                assert.equal(certUtil.conversions.beautifyDnString("cn=foo"), "CN=foo", "Single DN Part");
                assert.equal(certUtil.conversions.beautifyDnString("Cn=foo"), "CN=foo", "Camel DN Type");
                assert.equal(certUtil.conversions.beautifyDnString("cn=Capitalized Name"),
                    "CN=Capitalized Name",
                    "Capitalized Name");
                assert.equal(certUtil.conversions.beautifyDnString("cn=dan,o=zkpki,c=US"),
                    "CN=dan,O=zkpki,C=US",
                    "Multipart DN");
            });

        it("DN String to DN Data Types and Values",
            async function() {
                assert.ok(false); // TODO:
            });

        it("DN Types and Values to DN String",
            async function() {
                assert.ok(false); // TODO:
            });

        it("Get Certificate Date Range",
            async function() {
                assert.ok(false); // TODO:
            });

        it("BER Array to PEM String",
            async function() {
                assert.ok(false); // TODO:
            });

        it("PEM String to BER Array",
            async function() {
                assert.ok(false); // TODO:
            });
    });

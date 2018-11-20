const assert = require('assert');
const crypto = require('../../lib/crypto')

describe("Storage tests for file provider", function () {
    it("randomBytes()", () => {
        var bytes = crypto.randomBytes(32);
        assert.equal(bytes.length, 32);
    });

    it("hashBytes()", function () {
        var clearText = "This is the clear text.  Can you see it?";
        var hashValue = crypto.hashBytes(clearText);
        
        assert.equal(hashValue, "CcjornhoRXZ45nTn2FTUFMXf2huPZCNfXpHgbZ9CS31E");
    });

    it("encryptBytes() and decrytBytes()", function () {
        var clearText = "This is the clear text.  Can you see it?";
        var key = crypto.randomBytes(32);
        var cypherText = crypto.encryptBytes(key, clearText);

        assert.equal(crypto.decryptBytes(key, cypherText), clearText);
    });

    it("encryptBytes() and decryptBytes with empty buffer", () => {
        var clearText = "";
        var key = crypto.randomBytes(32);
        var cypherText = crypto.encryptBytes(key, clearText);
        assert.equal(crypto.decryptBytes(key, cypherText), clearText);
    });
});

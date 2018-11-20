const assert = require("assert");
const crypto = require("../../lib/crypto");

/*eslint no-undef: 0*/
describe("Storage tests for file provider", function () {
    it("randomBytes()", () => {
        let bytes = crypto.randomBytes(32);
        assert.equal(bytes.length, 32);
    });

    it("hashBytes()", function () {
        let clearText = "This is the clear text.  Can you see it?";
        let hashValue = crypto.hashBytes(clearText);
        
        assert.equal(hashValue, "CcjornhoRXZ45nTn2FTUFMXf2huPZCNfXpHgbZ9CS31E");
    });

    it("encryptBytes() and decrytBytes()", function () {
        let clearText = "This is the clear text.  Can you see it?";
        let key = crypto.randomBytes(32);
        let cypherText = crypto.encryptBytes(key, clearText);

        assert.equal(crypto.decryptBytes(key, cypherText), clearText);
    });

    it("encryptBytes() and decryptBytes with empty buffer", () => {
        let clearText = "";
        let key = crypto.randomBytes(32);
        let cypherText = crypto.encryptBytes(key, clearText);
        assert.equal(crypto.decryptBytes(key, cypherText), clearText);
    });
});

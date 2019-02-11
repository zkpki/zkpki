const base58 = require("bs58");
const crypto = require("crypto");

exports.encryptBytes = (key, buffer) => {
    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv("aes-256-cbc", new Buffer(key), iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return Buffer.concat([iv, encrypted]);
};

exports.decryptBytes = (key, encrypted) => {
    let iv = encrypted.slice(0, 16);
    let cyphertext = encrypted.slice(16, encrypted.length);
    let decipher = crypto.createDecipheriv("aes-256-cbc", new Buffer(key), iv);
    let decrypted = decipher.update(cyphertext);
    return Buffer.concat([decrypted, decipher.final()]);
};

exports.hashBytes = (buf, encoding = "base58") => {

    if (encoding === "base58") {
        return base58.encode(crypto.createHash("sha256").update(buf).digest());
    }
    return crypto.createHash("sha256").update(buf).digest(encoding);
};

exports.randomBytes = (size) => {
    return crypto.randomBytes(size);
};

const { promisify } = require("util");
const fs = require("fs");
const crypto = require("../../crypto");

const readfileAsync = promisify(fs.readFile);
const writefileAsync = promisify(fs.writeFile);
const statFileAsync = promisify(fs.stat);
const unlinkFileAsync = promisify(fs.unlink);

function generateFilename(key, options) {
    return options.path + "/" + crypto.hashBytes(key);
}

exports.create = async (key, options) => {
    const filename = generateFilename(key, options);
    try {
        await statFileAsync(filename);       
    }
    catch (err) {
        try {
            await writefileAsync(filename, crypto.encryptBytes(key, ""));
            return exports.open(key, options);
        }
        catch (err) {
            throw err;
        }
    }

    let err = new Error("File already exists: " + filename);
    err.code = "EEXIST";
    throw err;
};

exports.open = async (key, options) => { 
    const filename = generateFilename(key, options);
    try {
        await statFileAsync(filename);
        return {
            key: key,
            filename: filename,
            get: async () => {
                return crypto.decryptBytes(key, await readfileAsync(filename));
            },
            set: async (buf) => {
                return await writefileAsync(filename, crypto.encryptBytes(key, buf));
            }
        };
    }
    catch (err) {  
        throw err;        
    }  
};

exports.delete = async (key, options) => {
    const filename = generateFilename(key, options);
    unlinkFileAsync(filename);
};

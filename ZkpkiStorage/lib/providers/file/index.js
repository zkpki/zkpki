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

exports.open = async (key, options) => { 
    const filename = generateFilename(key, options);
    let result = {
        key: key,
        filename: filename,
        get: async () => {            
            return crypto.decryptBytes(key, await readfileAsync(filename));
        },
        set: async (buf) => {
            return await writefileAsync(filename, crypto.encryptBytes(key,buf));
        }
    };

    try {
        await statFileAsync(filename);
        return result;
    }
    catch (err) {
        try {
            await writefileAsync(filename, crypto.encryptBytes(key,""));
            return result;
        }
        catch (err) {
            throw err;
        }
    }  
};

exports.delete = async (key, options) => {
    const filename = generateFilename(key, options);
    unlinkFileAsync(filename);
};

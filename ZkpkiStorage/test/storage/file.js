const assert = require('assert');
const { promisify } = require('util');
const fs = require('fs'); 
const unlinkFileAsync = promisify(fs.unlink);
const statFileAsync = promisify(fs.stat);

const storage = require('../../lib/storage').file

describe("Storage tests for file provider",  () => { 

    var blob;
    var key = "Ohneo4ahthahSeG9AeT0thai4Moineex";
    var keyHash = "HBkpxPmA2123XGEGXpxVwcfDyi71ViNemDw46ohq1BdC"

    beforeEach(async () => {
        blob = await storage.open(key, { path: "./test" });
    });

    it("test open()", async () => {        
        assert.equal(blob.key, key);
        assert.equal(blob.filename, "./test/" + keyHash);
    });

    it("test open() again", async () => {
        var client = await storage.open(key, { path: "./test" });        
        assert.equal(client.key, key);
        assert.equal(client.filename, "./test/" + keyHash);
        assert.equal(await client.get(), "");
    });
    
    it("test set() and get()", async () => {
        var value = "This is a crazy cool value";
        await blob.set(value)
        result = await blob.get();
        assert.equal(result, value);        
    });

    it("test delete()", async () => {        
        var filename = blob.filename;
        await storage.delete(key, { path: "./test" });        
        try {
            await statFileAsync(filename);
            assert.ok(false); // should have thrown!
        }
        catch (err) {
        };
    });

    after(async () => {
        try {
            await unlinkFileAsync(blob.filename);
        }
        catch(err){
            // ignore unlink errors
        }
    });
});

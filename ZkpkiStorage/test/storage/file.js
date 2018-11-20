const assert = require("assert");
const { promisify } = require("util");
const fs = require("fs"); 
const unlinkFileAsync = promisify(fs.unlink);
const statFileAsync = promisify(fs.stat);

const storage = require("../../lib/storage").file;

/*eslint no-undef: 0*/
describe("Storage tests for file provider",  () => { 

    let blob;
    let key = "Ohneo4ahthahSeG9AeT0thai4Moineex";
    let keyHash = "HBkpxPmA2123XGEGXpxVwcfDyi71ViNemDw46ohq1BdC";

    beforeEach(async () => {
        blob = await storage.open(key, { path: "./test" });
    });

    it("test open()", async () => {        
        assert.equal(blob.key, key);
        assert.equal(blob.filename, "./test/" + keyHash);
    });

    it("test open() again", async () => {
        let client = await storage.open(key, { path: "./test" });        
        assert.equal(client.key, key);
        assert.equal(client.filename, "./test/" + keyHash);
        assert.equal(await client.get(), "");
    });
    
    it("test set() and get()", async () => {
        let value = "This is a crazy cool value";
        await blob.set(value);
        let result = await blob.get();
        assert.equal(result, value);        
    });

    it("test delete()", async () => {        
        let filename = blob.filename;
        await storage.delete(key, { path: "./test" });        
        try {
            await statFileAsync(filename);
            assert.ok(false); // should have thrown!
        }
        catch (err) {
            // Empty
        }
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

const assert = require("assert");
const { promisify } = require("util");
const fs = require("fs"); 
const unlinkFileAsync = promisify(fs.unlink);
const statFileAsync = promisify(fs.stat);

const storage = require("../../lib/storage").file;

/*eslint no-undef: 0*/
describe("Storage tests for file provider",  () => { 
    const key = "Ohneo4ahthahSeG9AeT0thai4Moineex";
    const keyHash = "HBkpxPmA2123XGEGXpxVwcfDyi71ViNemDw46ohq1BdC";
    const options = { path: "./test" };
    const expectedFilename = "./test/" + keyHash;     
            
    it("test open() with no create", async () => {                
        try {
            await storage.open(key, options);
            assert.ok(false); // should have thrown!
        }
        catch (err) {
            // Empty
            
        }        
    });

    it("test create()", async () => {
        let client = await storage.create(key, options);        
        assert.equal(client.key, key);
        assert.equal(client.filename, expectedFilename);
        assert.equal(await client.get(), "");       
    });

    it("test create() then open()", async () => {
        await storage.create(key, options);
        let client = await storage.open(key, options);
        assert.equal(client.key, key);
        assert.equal(client.filename, expectedFilename);
        assert.equal(await client.get(), "");
    });

    it("test double create()", async () => {
        await storage.create(key, options);
        try {
            await storage.create(key, options);
            assert.ok(false); // should have thrown!
        }
        catch (err) {
            // Empty           
        } 
    });
                
    it("test set() and get()", async () => {        
        let value = "This is a crazy cool value";
        let client = await storage.create(key, options);
        await client.set(value);
        let result = await client.get();
        assert.equal(result, value);        
    });

    it("test create() then delete()", async () => { 
        await storage.create(key, options);       
        await storage.delete(key, options);        
        try {
            await statFileAsync(expectedFilename);
            assert.ok(false); // should have thrown!
        }
        catch (err) {
            // Empty
        }
    });

    beforeEach(async () => {
        try {
            await unlinkFileAsync(expectedFilename);
        }
        catch (err) {
            // ignore unlink errors
        }
    });

    afterEach(async () => {
        try {
            await unlinkFileAsync(expectedFilename);
        }
        catch(err){
            // ignore unlink errors
        }
    });
});

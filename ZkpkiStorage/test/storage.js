var assert = require("assert");
var storage = require("../lib/storage");

describe("Storage", function () {

    it("Check providers", async () => {        
        assert.ok(storage.file, "Couldn't find storage.file");
        assert.ok(storage.file.open, "Couldn't find storage.file doesn't have open()");       
    });
    
});

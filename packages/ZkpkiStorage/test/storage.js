const assert = require("assert");
const storage = require("../lib/storage");

/*eslint no-undef: 0*/
describe("Storage", function () {

    it("Check providers", async () => {        
        assert.ok(storage.file, "Couldn't find storage.file");
        assert.ok(storage.file.open, "Couldn't find storage.file doesn't have open()");       
    });
    
});

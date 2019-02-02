# ZkpkiStorage

A simple blob storage abstraction for Zkpki. 

ZkpkiStorage hides the details of encrypting and storing data.  There is 
a pluggable provider facility that allows implementations for multiple
storage mechanisms. 

## Usage

```javascript
// File may be replaced with alternative storage implementation
const storage = require('../../lib/storage').file

// Open a storage using associated key and options.
var data = await storage.open(key, options);

// get the contents of the blob as a Buffer
var buf = await data.get();

// set the contents of the blob to specified Buffer
await data.set(buf);

// Delete the blob associated with a key and options
await storage.delete(key, options);
```

The `key` argument is always a 32 byte Buffer.  ZkpkiStorage providers
guarentee that a blob created/opened with a key can be opened again 
(or deleted) using the same key. 

To "rename" a blob, the caller would do something like the following:
```javascript
var data = await storage.open(oldkey,options);
var buf = await data.get();
var newData = await storage.create(newKey,options);
await newData.set(buf);
await storage.delete((oldkey,options);
```

## Providers and Options

The `options` parmeter is defined by the provider implementation.

### file
The file provider stores blobs in a local filesystem directory specified by 
the caller.
```
var options = {
	// The data storage path where blobs will be stored
	path: "/home/petrsnm/.zkpki/storage"
}
```

### Other provider options (coming soon)
As new providers are implemented, documentation of their `options` will be 
documented here... 

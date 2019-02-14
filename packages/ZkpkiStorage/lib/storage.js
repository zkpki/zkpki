let providers = [
    "file",
];

let storage = exports;

providers.forEach(function (provider) {
    storage.__defineGetter__(provider, function () {
        return require("./providers/" + provider);
    });
});


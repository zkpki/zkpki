var providers = [
    "file"
];

providers.forEach(function (provider) {
    exports.__defineGetter__(provider, function () {
        return require("./providers/" + provider);
    });
});


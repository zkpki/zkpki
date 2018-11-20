
var storage = exports;

var providers = [
    "file"
];

providers.forEach(function (provider) {
    storage.__defineGetter__(provider, function () {
        return require('./providers/' + provider);
    });
});


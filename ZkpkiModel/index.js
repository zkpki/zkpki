"use strict";

let ZkPkiModel = function() {
    const zkpkiCertFactory = require("./zkpkicertfactory");

    const tenYears = 3652;

    // properties
    this.rootCa = null;
    this.certificates = [];
    this.settings = null; // TODO:

    // reveal cert-util
    this.certUtil = require("./cert-util");

    // methods
    this.initialize = async (distinguishedName, algorithm, keySize) => {
        this.rootCa = zkpkiCertFactory.createCertificateAuthority(distinguishedName, tenYears, algorithm, keySize);
        this.certificates = []; // clear out certificates
    }
}

module.exports = new ZkPkiModel();


/*
 exports.deserialize = async (payload) => {
    // TODO: deserialize from decrypted payload

};

exports.serialize = async () => {
    // TODO: serialize the model and return it

    return "";
}

exports.issueCertificate = (options) => {

}

*/

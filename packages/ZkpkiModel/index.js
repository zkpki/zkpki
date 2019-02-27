"use strict";

let ZkPkiModel = function() {
    const zkPkiCertFactory = require("./lib/zkpkicertfactory");

    const tenYears = 3652;

    // private functions
    function getZkPkiCertSerializationData(zkPkiCert) {
        // only serialize the PEM data
        return {
            certificatePemData: zkPkiCert.certificatePemData,
            privateKeyPemData: zkPkiCert.privateKeyPemData
        };
    }

    // properties
    this.rootCa = null;
    this.certificates = [];
    this.settings = null; // store whatever you like here

    // reveal cert-util
    const certUtil = require("./lib/cert-util");
    this.ALGORITHMS = certUtil.ALGORITHMS;
    this.ELLIPTIC_CURVE_NAMES = certUtil.ELLIPTIC_CURVE_NAMES;
    this.KEY_USAGES = certUtil.KEY_USAGES;
    this.EXTENDED_KEY_USAGES = certUtil.EXTENDED_KEY_USAGES;

    // methods
    this.initialize = async (distinguishedName, algorithm, keySizeOrCurveName) => {
        this.rootCa =
            await zkPkiCertFactory.createCertificateAuthority(distinguishedName,
                tenYears, algorithm, keySizeOrCurveName);
        this.certificates = []; // clear out certificates
    }
    this.serialize = async () => {
        const modelObject = {
            rootCa: getZkPkiCertSerializationData(this.rootCa),
            settings: this.settings
        };
        modelObject.certificates = [];
        this.certificates.forEach(function(zkPkiCertificate) {
            modelObject.push(getZkPkiCertSerializationData(zkPkiCertificate));
        });
        return JSON.stringify(modelObject);
    }
    this.deserialize = async (data) => {
        const modelObject = JSON.parse(data);
        this.rootCa = await zkPkiCertFactory.loadCertificate(modelObject.rootCa);
        this.certificates = []; // clear out certificates and reload
        for (let zkPkiCert of modelObject.certificates) {
            this.certificates.push(await zkPkiCertFactory.loadCertificate(zkPkiCert));
        }
        this.settings = modelObject.settings;
    }
    this.issueCertificate = async (commonName, algorithm, keySizeOrCurveName, parameters) => {
        if (this.rootCa.certificate === null) {
            throw Error("Uninitialized ZkPkiModel does not contain a root CA.");
        }
        throw Error("Not implemented");
        // TODO:
        //const newKeyPair = await rawCert===
        //let zkPkiCert = await zkPkiCertFactory.createCertificate();
        //this.certificates.push(zkPkiCert);
        //return zkPkiCert;
    }
    this.issueCertificateForCsr = async (csr) => {
        if (this.rootCa.certificate === null) {
            throw Error("Uninitialized ZkPkiModel does not contain a root CA.");
        }
        // TODO:
    }
}

module.exports = new ZkPkiModel();

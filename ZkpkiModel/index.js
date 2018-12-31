"use strict";

let ZkPkiModel = function() {
    const zkpkiCertFactory = require("./lib/zkpkicertfactory");

    const tenYears = 3652;

    // properties
    this.rootCa = null;
    this.certificates = [];
    this.settings = null; // TODO:

    // reveal cert-util
    const certUtil = require("./lib/cert-util");
    this.ALGORITHMS = certUtil.ALGORITHMS;
    this.ELLIPTIC_CURVE_NAMES = certUtil.ELLIPTIC_CURVE_NAMES;
    this.KEY_USAGES = certUtil.KEY_USAGES;
    this.EXTENDED_KEY_USAGES = certUtil.EXTENDED_KEY_USAGES;

    // methods
    this.initialize = async (distinguishedName, algorithm, keySizeOrCurveName) => {
        this.rootCa =
            await zkpkiCertFactory.createCertificateAuthority(distinguishedName,
                tenYears, algorithm, keySizeOrCurveName);
        this.certificates = []; // clear out certificates
    }
    this.serialize = async () => {
        // TODO:
    }
    this.deserialize = async (data) => {
        // TODO:
    }
    this.issueCertificate = async (options) => {
        // TODO:
    }
    this.issueCertificateForCsr = async (csr) => {
        // TODO:
    }
}

module.exports = new ZkPkiModel();

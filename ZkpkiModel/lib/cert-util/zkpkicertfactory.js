"use strict";

let ZkPkiCertFactory = function () {
    const conversions = require("./conversions.js");
    const ZkPkiCert = require("./zkpkicert.js");

    this.create = async (parameters = {}) => {
        let cert = new ZkPkiCert(parameters);

        if (cert.certificatePemData === null && cert.certificate === null) {
            throw new Error("Unable to create ZkPkiCert with no certificate object and no PEM");
        } else if (cert.certificatePemData === null && cert.certificate !== null) {
            cert.certificatePemData = conversions.berToPem("CERTIFICATE", await cert.certificate.toSchema(true).toBER(false));
        } else if (cert.certificatePemData !== null && cert.certificate === null) {
            // TODO: parse
        }
        return cert;
    }
}

module.exports = new ZkPkiCertFactory();

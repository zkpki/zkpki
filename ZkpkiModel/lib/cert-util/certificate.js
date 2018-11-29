"use strict";

let cert = function(certificatePemData, privateKeyPemData) {
    if (certificatePemData !== undefined) {
        this.pemData = pemData;
        // TODO: parse?
        if (privateKeyPemData !== undefined) {
            this.privateKey = privateKeyPemData;
        }
    } else {
        this.pemData = null;
        this.serialNumber = null;
        this.subject = null;
        this.issuedDate = null;
        this.expirationDate = null;
        this.certificate = null;
        this.privateKey = null;
    }
}

cert.prototype.selfSign = function() {

}

module.exports = cert;

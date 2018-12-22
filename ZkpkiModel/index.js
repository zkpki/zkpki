"use strict";

// hack for console testing of cert-util... TODO: need proper model module
try {
    const certUtil = require("./lib/cert-util");
    certUtil.newRootCertificateAuthority("cn=dan,o=company,c=US").then(certificate => {
        console.log(certificate);
        console.log(certificate.certificate);
    }).catch(error => {
        console.log(error);
    });
} catch (error) {
    console.log(error);
}


/*
exports.initialize = async (distinguishedName, algorithm, keySize) => {
    // TODO: create new rootCa

}

 exports.deserialize = async (payload) => {
    // TODO: deserialize from decrypted payload

};

exports.serialize = async () => {
    // TODO: serialize the model and return it

    return "";
}

exports.issueCertificate = (options) => {

}



// TODO: key model properties

exports.rootCa = null;
exports.certificates = [];

// TODO: settings??

this.settings = null;


};
*/
'use strict';

/**
 * Digital signatures module.
 * @module Signatures
 * @author Catallaxy
 * @license LPGL3
 */

const openpgp = require('openpgp');

module.exports = {
  /**
   * Sign a file.
   * @exports Signatures/sign
   * @param {UInt8Array} message - The buffer of data to sign.
   * @param {PrivateKey} privateKey - The armored private key that will be used to sign.
   * @param {String} passphrase - The passphrase used to decrypt the private key.
   * @return {Promise} A promise that returns the signature (in a buffer).
   */
  sign(message, privateKey, passphrase) {
    try {
      const keyObject = openpgp.key.readArmored(privateKey),
        priv = keyObject.keys[0];

      return priv.decrypt(passphrase)
      .then(function done() {
        const signingOptions = {
            data: message,
            privateKeys: keyObject.keys,
            detached: true,
          };
        return openpgp.sign(signingOptions)
        .then(function done(signed) {
          const data = openpgp.armor.decode(signed.signature).data;
          return data;
        })
      })
    }
    catch(e) {
      console.error('error in parsing private key data', e.message || e);
      return Promise.reject(e);
    }
  },
};


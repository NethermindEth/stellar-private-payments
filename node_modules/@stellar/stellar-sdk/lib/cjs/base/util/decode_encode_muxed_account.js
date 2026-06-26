'use strict';

var buffer = require('buffer');
var curr_generated = require('../generated/curr_generated.js');
var strkey = require('../strkey.js');

function decodeAddressToMuxedAccount(address) {
  if (strkey.StrKey.isValidMed25519PublicKey(address)) {
    return _decodeAddressFullyToMuxedAccount(address);
  }
  return curr_generated.default.MuxedAccount.keyTypeEd25519(
    strkey.StrKey.decodeEd25519PublicKey(address)
  );
}
function encodeMuxedAccountToAddress(muxedAccount) {
  if (muxedAccount.switch().value === curr_generated.default.CryptoKeyType.keyTypeMuxedEd25519().value) {
    return _encodeMuxedAccountFullyToAddress(muxedAccount);
  }
  return strkey.StrKey.encodeEd25519PublicKey(muxedAccount.ed25519());
}
function encodeMuxedAccount(address, id) {
  if (!strkey.StrKey.isValidEd25519PublicKey(address)) {
    throw new Error("address should be a Stellar account ID (G...)");
  }
  if (typeof id !== "string") {
    throw new Error("id should be a string representing a number (uint64)");
  }
  return curr_generated.default.MuxedAccount.keyTypeMuxedEd25519(
    new curr_generated.default.MuxedAccountMed25519({
      id: curr_generated.default.Uint64.fromString(id),
      ed25519: strkey.StrKey.decodeEd25519PublicKey(address)
    })
  );
}
function extractBaseAddress(address) {
  if (strkey.StrKey.isValidEd25519PublicKey(address)) {
    return address;
  }
  if (!strkey.StrKey.isValidMed25519PublicKey(address)) {
    throw new TypeError(`expected muxed account (M...), got ${address}`);
  }
  const muxedAccount = decodeAddressToMuxedAccount(address);
  return strkey.StrKey.encodeEd25519PublicKey(muxedAccount.med25519().ed25519());
}
function _decodeAddressFullyToMuxedAccount(address) {
  const rawBytes = strkey.StrKey.decodeMed25519PublicKey(address);
  return curr_generated.default.MuxedAccount.keyTypeMuxedEd25519(
    new curr_generated.default.MuxedAccountMed25519({
      id: curr_generated.default.Uint64.fromXDR(rawBytes.subarray(-8)),
      ed25519: rawBytes.subarray(0, -8)
    })
  );
}
function _encodeMuxedAccountFullyToAddress(muxedAccount) {
  if (muxedAccount.switch() === curr_generated.default.CryptoKeyType.keyTypeEd25519()) {
    return encodeMuxedAccountToAddress(muxedAccount);
  }
  const muxed = muxedAccount.med25519();
  return strkey.StrKey.encodeMed25519PublicKey(
    buffer.Buffer.concat([muxed.ed25519(), muxed.id().toXDR("raw")])
  );
}

exports.decodeAddressToMuxedAccount = decodeAddressToMuxedAccount;
exports.encodeMuxedAccount = encodeMuxedAccount;
exports.encodeMuxedAccountToAddress = encodeMuxedAccountToAddress;
exports.extractBaseAddress = extractBaseAddress;
//# sourceMappingURL=decode_encode_muxed_account.js.map

import { Buffer } from 'buffer';
import types from '../generated/curr_generated.js';
import { StrKey } from '../strkey.js';

function decodeAddressToMuxedAccount(address) {
  if (StrKey.isValidMed25519PublicKey(address)) {
    return _decodeAddressFullyToMuxedAccount(address);
  }
  return types.MuxedAccount.keyTypeEd25519(
    StrKey.decodeEd25519PublicKey(address)
  );
}
function encodeMuxedAccountToAddress(muxedAccount) {
  if (muxedAccount.switch().value === types.CryptoKeyType.keyTypeMuxedEd25519().value) {
    return _encodeMuxedAccountFullyToAddress(muxedAccount);
  }
  return StrKey.encodeEd25519PublicKey(muxedAccount.ed25519());
}
function encodeMuxedAccount(address, id) {
  if (!StrKey.isValidEd25519PublicKey(address)) {
    throw new Error("address should be a Stellar account ID (G...)");
  }
  if (typeof id !== "string") {
    throw new Error("id should be a string representing a number (uint64)");
  }
  return types.MuxedAccount.keyTypeMuxedEd25519(
    new types.MuxedAccountMed25519({
      id: types.Uint64.fromString(id),
      ed25519: StrKey.decodeEd25519PublicKey(address)
    })
  );
}
function extractBaseAddress(address) {
  if (StrKey.isValidEd25519PublicKey(address)) {
    return address;
  }
  if (!StrKey.isValidMed25519PublicKey(address)) {
    throw new TypeError(`expected muxed account (M...), got ${address}`);
  }
  const muxedAccount = decodeAddressToMuxedAccount(address);
  return StrKey.encodeEd25519PublicKey(muxedAccount.med25519().ed25519());
}
function _decodeAddressFullyToMuxedAccount(address) {
  const rawBytes = StrKey.decodeMed25519PublicKey(address);
  return types.MuxedAccount.keyTypeMuxedEd25519(
    new types.MuxedAccountMed25519({
      id: types.Uint64.fromXDR(rawBytes.subarray(-8)),
      ed25519: rawBytes.subarray(0, -8)
    })
  );
}
function _encodeMuxedAccountFullyToAddress(muxedAccount) {
  if (muxedAccount.switch() === types.CryptoKeyType.keyTypeEd25519()) {
    return encodeMuxedAccountToAddress(muxedAccount);
  }
  const muxed = muxedAccount.med25519();
  return StrKey.encodeMed25519PublicKey(
    Buffer.concat([muxed.ed25519(), muxed.id().toXDR("raw")])
  );
}

export { decodeAddressToMuxedAccount, encodeMuxedAccount, encodeMuxedAccountToAddress, extractBaseAddress };
//# sourceMappingURL=decode_encode_muxed_account.js.map

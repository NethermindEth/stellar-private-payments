'use strict';

var curr_generated = require('./generated/curr_generated.js');
var account = require('./account.js');
var strkey = require('./strkey.js');
var decode_encode_muxed_account = require('./util/decode_encode_muxed_account.js');

const MAX_UINT64 = BigInt("18446744073709551615");
function validateUint64Id(id) {
  let value;
  try {
    value = BigInt(id);
  } catch {
    throw new Error(`id is not a valid uint64 string: ${id}`);
  }
  if (value < BigInt(0) || value > MAX_UINT64) {
    throw new Error(
      `id value out of range for uint64 [0, ${MAX_UINT64}]: ${id}`
    );
  }
}
class MuxedAccount {
  account;
  _muxedXdr;
  _mAddress;
  _id;
  /**
   * @param baseAccount - the {@link Account} instance representing the
   *     underlying G... address
   * @param id - a stringified uint64 value that represents the ID of the
   *     muxed account
   */
  constructor(baseAccount, id) {
    const accountId = baseAccount.accountId();
    if (!strkey.StrKey.isValidEd25519PublicKey(accountId)) {
      throw new Error("accountId is invalid");
    }
    validateUint64Id(id);
    this.account = baseAccount;
    this._muxedXdr = decode_encode_muxed_account.encodeMuxedAccount(accountId, id);
    this._mAddress = decode_encode_muxed_account.encodeMuxedAccountToAddress(this._muxedXdr);
    this._id = id;
  }
  /**
   * Parses an M-address into a MuxedAccount object.
   *
   * @param  mAddress    - an M-address to transform
   * @param  sequenceNum - the sequence number of the underlying {@link
   *     Account}, to use for the underlying base account {@link
   *     MuxedAccount.baseAccount}. If you're using the SDK, you can use
   *     `server.loadAccount` to fetch this if you don't know it.
   */
  static fromAddress(mAddress, sequenceNum) {
    const muxedAccount = decode_encode_muxed_account.decodeAddressToMuxedAccount(mAddress);
    const gAddress = decode_encode_muxed_account.extractBaseAddress(mAddress);
    const id = muxedAccount.med25519().id().toString();
    return new MuxedAccount(new account.Account(gAddress, sequenceNum), id);
  }
  /**
   * Returns the underlying account object shared among all muxed
   * accounts with this Stellar address.
   */
  baseAccount() {
    return this.account;
  }
  /**
   * Returns the M-address representing this account's (G-address, ID).
   */
  accountId() {
    return this._mAddress;
  }
  /**
   * Returns the uint64 ID of this muxed account as a string.
   */
  id() {
    return this._id;
  }
  /**
   * Updates the muxed account's ID, regenerating the M-address accordingly.
   *
   * @param id - a stringified uint64 value to set as the new muxed account ID
   */
  setId(id) {
    if (typeof id !== "string") {
      throw new Error("id should be a string representing a number (uint64)");
    }
    validateUint64Id(id);
    this._muxedXdr.med25519().id(curr_generated.default.Uint64.fromString(id));
    this._mAddress = decode_encode_muxed_account.encodeMuxedAccountToAddress(this._muxedXdr);
    this._id = id;
    return this;
  }
  /**
   * Returns the stringified sequence number for the underlying account.
   */
  sequenceNumber() {
    return this.account.sequenceNumber();
  }
  /**
   * Increments the underlying account's sequence number by one.
   */
  incrementSequenceNumber() {
    this.account.incrementSequenceNumber();
  }
  /**
   * Returns the XDR object representing this muxed account's
   * G-address and uint64 ID.
   */
  toXDRObject() {
    return this._muxedXdr;
  }
  /**
   * Checks whether two muxed accounts are equal by comparing their M-addresses.
   *
   * @param otherMuxedAccount - the MuxedAccount to compare against
   */
  equals(otherMuxedAccount) {
    return this.accountId() === otherMuxedAccount.accountId();
  }
}

exports.MuxedAccount = MuxedAccount;
//# sourceMappingURL=muxed_account.js.map

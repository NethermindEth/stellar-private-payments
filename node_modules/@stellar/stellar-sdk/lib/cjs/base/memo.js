'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
var unsignedHyper = require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
var bignumber = require('./util/bignumber.js');
var curr_generated = require('./generated/curr_generated.js');

const MemoNone = "none";
const MemoID = "id";
const MemoText = "text";
const MemoHash = "hash";
const MemoReturn = "return";
class Memo {
  _type;
  _value;
  /**
   * @param type - `MemoNone`, `MemoID`, `MemoText`, `MemoHash` or `MemoReturn`
   * @param value - `string` for `MemoID`, `MemoText`, buffer or hex string for `MemoHash` or `MemoReturn`
   */
  constructor(type, value = null) {
    this._type = type;
    this._value = value;
    switch (this._type) {
      case MemoNone:
        break;
      case MemoID:
        Memo._validateIdValue(value);
        break;
      case MemoText:
        Memo._validateTextValue(value);
        break;
      case MemoHash:
      case MemoReturn:
        Memo._validateHashValue(value);
        if (typeof value === "string") {
          this._value = buffer.Buffer.from(value, "hex");
        }
        break;
      default:
        throw new Error("Invalid memo type");
    }
  }
  /**
   * Contains memo type: `MemoNone`, `MemoID`, `MemoText`, `MemoHash` or `MemoReturn`
   */
  get type() {
    return this._type;
  }
  set type(_type) {
    throw new Error("Memo is immutable");
  }
  /**
   * Contains memo value:
   * * `null` for `MemoNone`,
   * * `string` for `MemoID`,
   * * `Buffer` for `MemoText` after decoding using `fromXDRObject`, original value otherwise,
   * * `Buffer` for `MemoHash`, `MemoReturn`.
   */
  get value() {
    switch (this._type) {
      case MemoNone:
        return null;
      case MemoID:
      case MemoText:
        return this._value;
      case MemoHash:
      case MemoReturn:
        return buffer.Buffer.from(this._value);
      default:
        throw new Error("Invalid memo type");
    }
  }
  set value(_value) {
    throw new Error("Memo is immutable");
  }
  static _validateIdValue(value) {
    const error = new Error(`Expects a uint64 as a string. Got ${value}`);
    if (typeof value !== "string") {
      throw error;
    }
    if (!/^[0-9]+$/.test(value)) {
      throw error;
    }
    let number;
    try {
      number = new bignumber.default(value);
    } catch {
      throw error;
    }
    if (!number.isFinite()) {
      throw error;
    }
    if (number.isNaN()) {
      throw error;
    }
    if (number.isNegative()) {
      throw error;
    }
    if (!number.isInteger()) {
      throw error;
    }
    if (number.isGreaterThan("18446744073709551615")) {
      throw error;
    }
  }
  static _validateTextValue(value) {
    if (typeof value === "string") {
      if (buffer.Buffer.byteLength(value, "utf8") > 28) {
        throw new Error("Expects string, array or buffer, max 28 bytes");
      }
    } else if (buffer.Buffer.isBuffer(value)) {
      if (value.length > 28) {
        throw new Error("Expects string, array or buffer, max 28 bytes");
      }
    } else {
      if (!curr_generated.default.Memo.armTypeForArm("text").isValid(value)) {
        throw new Error("Expects string, array or buffer, max 28 bytes");
      }
    }
  }
  static _validateHashValue(value) {
    const error = new Error(
      `Expects a 32 byte hash value or hex encoded string. Got ${String(value)}`
    );
    if (value === null || typeof value === "undefined") {
      throw error;
    }
    let valueBuffer;
    if (typeof value === "string") {
      if (!/^[0-9A-Fa-f]{64}$/g.test(value)) {
        throw error;
      }
      valueBuffer = buffer.Buffer.from(value, "hex");
    } else if (buffer.Buffer.isBuffer(value)) {
      valueBuffer = buffer.Buffer.from(value);
    } else {
      throw error;
    }
    if (!valueBuffer.length || valueBuffer.length !== 32) {
      throw error;
    }
  }
  /**
   * Returns an empty memo (`MemoNone`).
   */
  static none() {
    return new Memo(MemoNone);
  }
  /**
   * Creates and returns a `MemoText` memo.
   *
   * @param text - memo text
   */
  static text(text) {
    return new Memo(MemoText, text);
  }
  /**
   * Creates and returns a `MemoID` memo.
   *
   * @param id - 64-bit number represented as a string
   */
  static id(id) {
    return new Memo(MemoID, id);
  }
  /**
   * Creates and returns a `MemoHash` memo.
   *
   * @param hash - 32 byte hash or hex encoded string
   */
  static hash(hash) {
    return new Memo(MemoHash, hash);
  }
  /**
   * Creates and returns a `MemoReturn` memo.
   *
   * @param hash - 32 byte hash or hex encoded string
   */
  static return(hash) {
    return new Memo(MemoReturn, hash);
  }
  /**
   * Returns XDR memo object.
   */
  toXDRObject() {
    switch (this._type) {
      case MemoNone:
        return curr_generated.default.Memo.memoNone();
      case MemoID:
        return curr_generated.default.Memo.memoId(
          curr_generated.default.Uint64.fromString(
            unsignedHyper.UnsignedHyper.fromString(this._value).toString()
          )
        );
      case MemoText:
        return curr_generated.default.Memo.memoText(this._value);
      case MemoHash:
        return curr_generated.default.Memo.memoHash(this._value);
      case MemoReturn:
        return curr_generated.default.Memo.memoReturn(this._value);
      default:
        throw new Error("Invalid memo type");
    }
  }
  /**
   * Returns {@link Memo} from XDR memo object.
   *
   * @param object - XDR memo object
   */
  static fromXDRObject(object) {
    switch (object.switch()) {
      case curr_generated.default.MemoType.memoId():
        return Memo.id(object.id().toString());
      case curr_generated.default.MemoType.memoText():
        return Memo.text(object.value());
      case curr_generated.default.MemoType.memoHash():
        return Memo.hash(object.hash());
      case curr_generated.default.MemoType.memoReturn():
        return Memo.return(object.retHash());
    }
    if (typeof object.value() === "undefined") {
      return Memo.none();
    }
    throw new Error("Unknown type");
  }
}

exports.Memo = Memo;
exports.MemoHash = MemoHash;
exports.MemoID = MemoID;
exports.MemoNone = MemoNone;
exports.MemoReturn = MemoReturn;
exports.MemoText = MemoText;
//# sourceMappingURL=memo.js.map

'use strict';

require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
var hyper = require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
var unsignedHyper = require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var uint128 = require('./uint128.js');
var uint256 = require('./uint256.js');
var int128 = require('./int128.js');
var int256 = require('./int256.js');
var curr_generated = require('../generated/curr_generated.js');

class XdrLargeInt {
  int;
  type;
  /**
   * @param type - specifies a data type to use to represent the integer, one
   *    of: 'i64', 'u64', 'i128', 'u128', 'i256', 'u256', 'timepoint', and 'duration'
   *    (see {@link XdrLargeInt.isType})
   * @param values - a list of integer-like values interpreted in big-endian order
   */
  constructor(type, values) {
    if (!(values instanceof Array)) {
      values = [values];
    }
    const normalizedValues = values.map((i) => {
      if (typeof i === "bigint") {
        return i;
      }
      if (typeof i === "object" && i !== null && "toBigInt" in i && typeof i.toBigInt === "function") {
        return i.toBigInt();
      }
      return BigInt(i);
    });
    switch (type) {
      case "i64":
        this.int = new hyper.Hyper(normalizedValues);
        break;
      case "i128":
        this.int = new int128.Int128(...normalizedValues);
        break;
      case "i256":
        this.int = new int256.Int256(...normalizedValues);
        break;
      case "u64":
      case "timepoint":
      case "duration":
        this.int = new unsignedHyper.UnsignedHyper(normalizedValues);
        break;
      case "u128":
        this.int = new uint128.Uint128(...normalizedValues);
        break;
      case "u256":
        this.int = new uint256.Uint256(...normalizedValues);
        break;
      default:
        throw TypeError(`invalid type: ${type}`);
    }
    this.type = type;
  }
  /**
   * Converts to a native JS number.
   *
   * @throws if the value can't fit into a Number
   */
  toNumber() {
    const bi = this.int.toBigInt();
    if (bi > Number.MAX_SAFE_INTEGER || bi < Number.MIN_SAFE_INTEGER) {
      throw RangeError(
        `value ${bi} not in range for Number [${Number.MAX_SAFE_INTEGER}, ${Number.MIN_SAFE_INTEGER}]`
      );
    }
    return Number(bi);
  }
  /** Converts to a native BigInt. */
  toBigInt() {
    return this.int.toBigInt();
  }
  /**
   * The integer encoded with `ScValType = I64`.
   *
   * @throws if the value cannot fit in 64 bits
   */
  toI64() {
    this._sizeCheck(64);
    const v = this.toBigInt();
    if (BigInt.asIntN(64, v) !== v) {
      throw RangeError(`value too large for i64: ${v}`);
    }
    return curr_generated.default.ScVal.scvI64(new curr_generated.default.Int64(v));
  }
  /** The integer encoded with `ScValType = U64` */
  toU64() {
    this._sizeCheck(64);
    return curr_generated.default.ScVal.scvU64(
      new curr_generated.default.Uint64(BigInt.asUintN(64, this.toBigInt()))
      // reiterpret as unsigned
    );
  }
  /** The integer encoded with `ScValType = Timepoint` */
  toTimepoint() {
    this._sizeCheck(64);
    return curr_generated.default.ScVal.scvTimepoint(
      new curr_generated.default.Uint64(BigInt.asUintN(64, this.toBigInt()))
      // reiterpret as unsigned
    );
  }
  /** The integer encoded with `ScValType = Duration` */
  toDuration() {
    this._sizeCheck(64);
    return curr_generated.default.ScVal.scvDuration(
      new curr_generated.default.Uint64(BigInt.asUintN(64, this.toBigInt()))
      // reiterpret as unsigned
    );
  }
  /**
   * The integer encoded with `ScValType = I128`.
   *
   * @throws if the value cannot fit in 128 bits
   */
  toI128() {
    this._sizeCheck(128);
    const v = this.int.toBigInt();
    if (BigInt.asIntN(128, v) !== v) {
      throw RangeError(`value too large for i128: ${v}`);
    }
    const hi64 = BigInt.asIntN(64, v >> 64n);
    const lo64 = BigInt.asUintN(64, v);
    return curr_generated.default.ScVal.scvI128(
      new curr_generated.default.Int128Parts({
        hi: new curr_generated.default.Int64(hi64),
        lo: new curr_generated.default.Uint64(lo64)
      })
    );
  }
  /**
   * The integer encoded with `ScValType = U128`.
   *
   * @throws if the value cannot fit in 128 bits
   */
  toU128() {
    this._sizeCheck(128);
    const v = this.int.toBigInt();
    return curr_generated.default.ScVal.scvU128(
      new curr_generated.default.UInt128Parts({
        hi: new curr_generated.default.Uint64(BigInt.asUintN(64, v >> 64n)),
        lo: new curr_generated.default.Uint64(BigInt.asUintN(64, v))
      })
    );
  }
  /**
   * The integer encoded with `ScValType = I256`
   *
   * @throws if the value cannot fit in a signed 256-bit integer
   */
  toI256() {
    const v = this.int.toBigInt();
    if (BigInt.asIntN(256, v) !== v) {
      throw RangeError(`value too large for i256: ${v}`);
    }
    const hiHi64 = BigInt.asIntN(64, v >> 192n);
    const hiLo64 = BigInt.asUintN(64, v >> 128n);
    const loHi64 = BigInt.asUintN(64, v >> 64n);
    const loLo64 = BigInt.asUintN(64, v);
    return curr_generated.default.ScVal.scvI256(
      new curr_generated.default.Int256Parts({
        hiHi: new curr_generated.default.Int64(hiHi64),
        hiLo: new curr_generated.default.Uint64(hiLo64),
        loHi: new curr_generated.default.Uint64(loHi64),
        loLo: new curr_generated.default.Uint64(loLo64)
      })
    );
  }
  /**
   * The integer encoded with `ScValType = U256`
   *
   * Note: No size check needed - U256 is the largest unsigned type.
   */
  toU256() {
    const v = this.int.toBigInt();
    const hiHi64 = BigInt.asUintN(64, v >> 192n);
    const hiLo64 = BigInt.asUintN(64, v >> 128n);
    const loHi64 = BigInt.asUintN(64, v >> 64n);
    const loLo64 = BigInt.asUintN(64, v);
    return curr_generated.default.ScVal.scvU256(
      new curr_generated.default.UInt256Parts({
        hiHi: new curr_generated.default.Uint64(hiHi64),
        hiLo: new curr_generated.default.Uint64(hiLo64),
        loHi: new curr_generated.default.Uint64(loHi64),
        loLo: new curr_generated.default.Uint64(loLo64)
      })
    );
  }
  /** The smallest interpretation of the stored value */
  toScVal() {
    switch (this.type) {
      case "i64":
        return this.toI64();
      case "i128":
        return this.toI128();
      case "i256":
        return this.toI256();
      case "u64":
        return this.toU64();
      case "u128":
        return this.toU128();
      case "u256":
        return this.toU256();
      case "timepoint":
        return this.toTimepoint();
      case "duration":
        return this.toDuration();
      default:
        throw TypeError(`invalid type: ${this.type}`);
    }
  }
  /** Returns the primitive value of this integer. */
  valueOf() {
    return this.int.valueOf();
  }
  /** Returns the string representation of this integer. */
  toString() {
    return this.int.toString();
  }
  /** Returns a JSON-friendly representation with `value` and `type` fields. */
  toJSON() {
    return {
      value: this.toBigInt().toString(),
      type: this.type
    };
  }
  _sizeCheck(bits) {
    if (this.int.size > bits) {
      throw RangeError(`value too large for ${bits} bits (${this.type})`);
    }
  }
  /** Returns true if the given string is a valid XDR large integer type name. */
  static isType(type) {
    switch (type) {
      case "i64":
      case "i128":
      case "i256":
      case "u64":
      case "u128":
      case "u256":
      case "timepoint":
      case "duration":
        return true;
      default:
        return false;
    }
  }
  /**
   * Convert the raw `ScValType` string (e.g. 'scvI128', generated by the XDR)
   * to a type description for {@link XdrLargeInt} construction (e.g. 'i128')
   *
   * @param scvType - the `xdr.ScValType` as a string
   * @returns the corresponding {@link ScIntType} if it's an integer type, or
   *    `undefined` if it's not an integer type
   */
  static getType(scvType) {
    const type = scvType.slice(3).toLowerCase();
    if (this.isType(type)) {
      return type;
    }
    return void 0;
  }
}

exports.XdrLargeInt = XdrLargeInt;
//# sourceMappingURL=xdr_large_int.js.map

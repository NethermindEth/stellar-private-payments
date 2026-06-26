'use strict';

var xdr_large_int = require('./xdr_large_int.js');
var uint128 = require('./uint128.js');
var uint256 = require('./uint256.js');
var int128 = require('./int128.js');
var int256 = require('./int256.js');

function scValToBigInt(scv) {
  const switchName = scv.switch().name;
  const scIntType = xdr_large_int.XdrLargeInt.getType(switchName);
  const value = scv.value();
  if (value === null) {
    throw TypeError(`unexpected null value for ${switchName}`);
  }
  switch (switchName) {
    case "scvU32":
    case "scvI32":
      return BigInt(value);
    case "scvU64":
    case "scvI64":
    case "scvTimepoint":
    case "scvDuration":
      if (scIntType === void 0) {
        throw TypeError(`invalid integer type for ${switchName}`);
      }
      return new xdr_large_int.XdrLargeInt(
        scIntType,
        value
      ).toBigInt();
    case "scvU128":
    case "scvI128": {
      if (scIntType === void 0) {
        throw TypeError(`invalid integer type for ${switchName}`);
      }
      const int128Value = value;
      return new xdr_large_int.XdrLargeInt(scIntType, [
        int128Value.lo(),
        int128Value.hi()
      ]).toBigInt();
    }
    case "scvU256":
    case "scvI256": {
      if (scIntType === void 0) {
        throw TypeError(`invalid integer type for ${switchName}`);
      }
      const int256Value = value;
      return new xdr_large_int.XdrLargeInt(scIntType, [
        int256Value.loLo(),
        int256Value.loHi(),
        int256Value.hiLo(),
        int256Value.hiHi()
      ]).toBigInt();
    }
    default:
      throw TypeError(`expected integer type, got ${switchName}`);
  }
}

exports.XdrLargeInt = xdr_large_int.XdrLargeInt;
exports.Uint128 = uint128.Uint128;
exports.Uint256 = uint256.Uint256;
exports.Int128 = int128.Int128;
exports.Int256 = int256.Int256;
exports.scValToBigInt = scValToBigInt;
//# sourceMappingURL=index.js.map

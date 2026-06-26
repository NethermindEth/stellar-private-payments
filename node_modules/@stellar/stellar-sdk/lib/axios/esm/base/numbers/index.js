import { XdrLargeInt } from './xdr_large_int.js';
export { Uint128 } from './uint128.js';
export { Uint256 } from './uint256.js';
export { Int128 } from './int128.js';
export { Int256 } from './int256.js';

function scValToBigInt(scv) {
  const switchName = scv.switch().name;
  const scIntType = XdrLargeInt.getType(switchName);
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
      return new XdrLargeInt(
        scIntType,
        value
      ).toBigInt();
    case "scvU128":
    case "scvI128": {
      if (scIntType === void 0) {
        throw TypeError(`invalid integer type for ${switchName}`);
      }
      const int128Value = value;
      return new XdrLargeInt(scIntType, [
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
      return new XdrLargeInt(scIntType, [
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

export { XdrLargeInt, scValToBigInt };
//# sourceMappingURL=index.js.map

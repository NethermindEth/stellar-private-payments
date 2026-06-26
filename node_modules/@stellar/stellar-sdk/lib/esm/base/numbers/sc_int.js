import { XdrLargeInt } from './xdr_large_int.js';

class ScInt extends XdrLargeInt {
  /**
   * @param value - a single, integer-like value which will
   *    be interpreted in the smallest appropriate XDR type supported by Stellar
   *    (64, 128, or 256 bit integer values). signed values are supported, though
   *    they are sanity-checked against `opts.type`. if you need 32-bit values,
   *    you can construct them directly without needing this wrapper, e.g.
   *    `xdr.ScVal.scvU32(1234)`.
   * @param opts - an optional object controlling optional parameters
   *   - `type`: specify a type ('i64', 'u64', 'i128', 'u128', 'i256',
   *    or 'u256') to override the default type selection. If not specified, the
   *    smallest type that fits the value is used.
   */
  constructor(value, opts) {
    const bigValue = BigInt(value);
    const signed = bigValue < 0n;
    let type = opts?.type ?? "";
    if (type.startsWith("u") && signed) {
      throw TypeError(`specified type ${opts?.type} yet negative (${value})`);
    }
    if (type === "") {
      type = signed ? "i" : "u";
      const bitlen = nearestBigIntSize(bigValue);
      switch (bitlen) {
        case 64:
        case 128:
        case 256:
          type += bitlen.toString();
          break;
        default:
          throw RangeError(
            `expected 64/128/256 bits for input (${value}), got ${bitlen}`
          );
      }
    }
    super(type, bigValue);
  }
}
function nearestBigIntSize(bigI) {
  if (bigI < 0n) {
    const abs = -bigI;
    const bitlen2 = (abs - 1n).toString(2).length + 1;
    return [64, 128, 256].find((len) => bitlen2 <= len) ?? bitlen2;
  }
  const bitlen = bigI.toString(2).length;
  return [64, 128, 256].find((len) => bitlen <= len) ?? bitlen;
}

export { ScInt };
//# sourceMappingURL=sc_int.js.map

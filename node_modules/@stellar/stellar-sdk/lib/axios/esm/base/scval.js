import { Buffer } from 'buffer';
import types from './generated/curr_generated.js';
import { Keypair } from './keypair.js';
import { Address } from './address.js';
import { Contract } from './contract.js';
import { scValToBigInt } from './numbers/index.js';
import { XdrLargeInt } from './numbers/xdr_large_int.js';
import { ScInt } from './numbers/sc_int.js';

function nativeToScVal(val, opts = {}) {
  switch (typeof val) {
    case "object": {
      if (val === null) {
        return types.ScVal.scvVoid();
      }
      if (val instanceof types.ScVal) {
        return val;
      }
      if (val instanceof Address) {
        return val.toScVal();
      }
      if (val instanceof Keypair) {
        return nativeToScVal(val.publicKey(), { type: "address" });
      }
      if (val instanceof Contract) {
        return val.address().toScVal();
      }
      if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
        const copy = Buffer.from(val);
        switch (opts?.type ?? "bytes") {
          case "bytes":
            return types.ScVal.scvBytes(copy);
          case "symbol":
            return types.ScVal.scvSymbol(copy);
          case "string":
            return types.ScVal.scvString(copy);
          default:
            throw new TypeError(
              `invalid type (${JSON.stringify(opts.type)}) specified for bytes-like value`
            );
        }
      }
      if (Array.isArray(val)) {
        return types.ScVal.scvVec(
          val.map((v, idx) => {
            if (Array.isArray(opts.type)) {
              return nativeToScVal(
                v,
                // only include a `{ type: ... }` if it's present (safer than
                // `{type: undefined}`)
                {
                  ...opts.type.length > idx && {
                    type: opts.type[idx]
                  }
                }
              );
            }
            return nativeToScVal(v, opts);
          })
        );
      }
      if (Object.getPrototypeOf(val) !== Object.prototype) {
        throw new TypeError(
          `cannot interpret ${val.constructor?.name} value as ScVal (${JSON.stringify(val)})`
        );
      }
      const mapTypeSpec = opts?.type ?? {};
      return types.ScVal.scvMap(
        Object.entries(val).sort(([key1], [key2]) => key1 < key2 ? -1 : key1 > key2 ? 1 : 0).map(([k, v]) => {
          const [keyType, valType] = Object.hasOwn(mapTypeSpec, k) ? mapTypeSpec[k] ?? [null, null] : [null, null];
          const keyOpts = keyType ? { type: keyType } : {};
          const valOpts = valType ? { type: valType } : {};
          return new types.ScMapEntry({
            key: nativeToScVal(k, keyOpts),
            val: nativeToScVal(v, valOpts)
          });
        })
      );
    }
    case "number":
    case "bigint": {
      const bigintVal = BigInt(val);
      switch (opts?.type) {
        case "u32":
          if (bigintVal < BigInt(types.Uint32.MIN_VALUE) || bigintVal > BigInt(types.Uint32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type u32`);
          }
          return types.ScVal.scvU32(Number(val));
        case "i32":
          if (bigintVal < -BigInt(types.Int32.MIN_VALUE) || bigintVal > BigInt(types.Int32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type i32`);
          }
          return types.ScVal.scvI32(Number(val));
      }
      return new ScInt(val, { type: opts?.type }).toScVal();
    }
    case "string": {
      const optType = opts?.type ?? "string";
      switch (optType) {
        case "string":
          return types.ScVal.scvString(val);
        case "symbol":
          return types.ScVal.scvSymbol(val);
        case "address":
          return new Address(val).toScVal();
        case "u32": {
          const bigintVal = BigInt(val);
          if (bigintVal < BigInt(types.Uint32.MIN_VALUE) || bigintVal > BigInt(types.Uint32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type u32`);
          }
          return types.ScVal.scvU32(Number(bigintVal));
        }
        case "i32": {
          const bigintVal = BigInt(val);
          if (bigintVal < -BigInt(types.Int32.MIN_VALUE) || bigintVal > BigInt(types.Int32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type i32`);
          }
          return types.ScVal.scvI32(Number(bigintVal));
        }
        default:
          if (XdrLargeInt.isType(optType)) {
            return new XdrLargeInt(optType, val).toScVal();
          }
          throw new TypeError(
            `invalid type (${JSON.stringify(opts.type)}) specified for string value`
          );
      }
    }
    case "boolean":
      return types.ScVal.scvBool(val);
    case "undefined":
      return types.ScVal.scvVoid();
    case "function":
      return nativeToScVal(val());
    default:
      throw new TypeError(
        `failed to convert typeof ${typeof val} (${JSON.stringify(val)})`
      );
  }
}
function scValToNative(scv) {
  switch (scv.switch().value) {
    case types.ScValType.scvVoid().value:
      return null;
    // these can be converted to bigints directly
    case types.ScValType.scvU64().value:
    case types.ScValType.scvI64().value:
      return scv.value().toBigInt();
    // these can be parsed by internal abstractions note that this can also
    // handle the above two cases, but it's not as efficient (another
    // type-check, parsing, etc.)
    case types.ScValType.scvU128().value:
    case types.ScValType.scvI128().value:
    case types.ScValType.scvU256().value:
    case types.ScValType.scvI256().value:
      return scValToBigInt(scv);
    case types.ScValType.scvVec().value:
      return (scv.vec() ?? []).map(scValToNative);
    case types.ScValType.scvAddress().value:
      return Address.fromScVal(scv).toString();
    case types.ScValType.scvMap().value:
      return Object.fromEntries(
        (scv.map() ?? []).map((entry) => [
          scValToNative(entry.key()),
          scValToNative(entry.val())
        ])
      );
    // these return the primitive type directly
    case types.ScValType.scvBool().value:
    case types.ScValType.scvU32().value:
    case types.ScValType.scvI32().value:
    case types.ScValType.scvBytes().value:
      return scv.value();
    // Symbols are limited to [a-zA-Z0-9_]+, so we can safely make ascii strings
    //
    // Strings, however, are "presented" as strings and we treat them as such
    // (in other words, string = bytes with a hint that it's text). If the user
    // encoded non-printable bytes in their string value, that's on them.
    //
    // Note that we assume a utf8 encoding (ascii-compatible). For other
    // encodings, you should probably use bytes anyway. If it cannot be decoded,
    // the raw bytes are returned.
    case types.ScValType.scvSymbol().value: {
      const v = scv.sym();
      if (Buffer.isBuffer(v) || ArrayBuffer.isView(v) && typeof v !== "string") {
        try {
          return new TextDecoder().decode(v);
        } catch {
          return new Uint8Array(v.buffer);
        }
      }
      return v;
    }
    case types.ScValType.scvString().value: {
      const v = scv.str();
      if (Buffer.isBuffer(v) || ArrayBuffer.isView(v) && typeof v !== "string") {
        try {
          return new TextDecoder().decode(v);
        } catch {
          return new Uint8Array(v.buffer);
        }
      }
      return v;
    }
    // these can be converted to bigint
    case types.ScValType.scvTimepoint().value:
    case types.ScValType.scvDuration().value:
      return scv.value().toBigInt();
    case types.ScValType.scvError().value:
      switch (scv.error().switch().value) {
        // Distinguish errors from the user contract.
        case types.ScErrorType.sceContract().value:
          return { type: "contract", code: scv.error().contractCode() };
        default: {
          const err = scv.error();
          return {
            type: "system",
            code: err.code().value,
            value: err.code().name
          };
        }
      }
    // in the fallthrough case, just return the underlying value directly
    default:
      return scv.value();
  }
}
function scvSortedMap(items) {
  const sorted = Array.from(items).sort((a, b) => {
    const nativeA = scValToNative(a.key());
    const nativeB = scValToNative(b.key());
    switch (typeof nativeA) {
      case "number":
      case "bigint":
        if (nativeA === nativeB) return 0;
        return nativeA < nativeB ? -1 : 1;
      default: {
        const strA = nativeA.toString();
        const strB = nativeB.toString();
        return strA < strB ? -1 : strA > strB ? 1 : 0;
      }
    }
  });
  return types.ScVal.scvMap(sorted);
}
types.scvSortedMap = scvSortedMap;

export { nativeToScVal, scValToNative, scvSortedMap };
//# sourceMappingURL=scval.js.map

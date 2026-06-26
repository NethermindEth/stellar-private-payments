'use strict';

var buffer = require('buffer');
var curr_generated = require('./generated/curr_generated.js');
var keypair = require('./keypair.js');
var address = require('./address.js');
var contract = require('./contract.js');
var index = require('./numbers/index.js');
var xdr_large_int = require('./numbers/xdr_large_int.js');
var sc_int = require('./numbers/sc_int.js');

function nativeToScVal(val, opts = {}) {
  switch (typeof val) {
    case "object": {
      if (val === null) {
        return curr_generated.default.ScVal.scvVoid();
      }
      if (val instanceof curr_generated.default.ScVal) {
        return val;
      }
      if (val instanceof address.Address) {
        return val.toScVal();
      }
      if (val instanceof keypair.Keypair) {
        return nativeToScVal(val.publicKey(), { type: "address" });
      }
      if (val instanceof contract.Contract) {
        return val.address().toScVal();
      }
      if (val instanceof Uint8Array || buffer.Buffer.isBuffer(val)) {
        const copy = buffer.Buffer.from(val);
        switch (opts?.type ?? "bytes") {
          case "bytes":
            return curr_generated.default.ScVal.scvBytes(copy);
          case "symbol":
            return curr_generated.default.ScVal.scvSymbol(copy);
          case "string":
            return curr_generated.default.ScVal.scvString(copy);
          default:
            throw new TypeError(
              `invalid type (${JSON.stringify(opts.type)}) specified for bytes-like value`
            );
        }
      }
      if (Array.isArray(val)) {
        return curr_generated.default.ScVal.scvVec(
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
      return curr_generated.default.ScVal.scvMap(
        Object.entries(val).sort(([key1], [key2]) => key1 < key2 ? -1 : key1 > key2 ? 1 : 0).map(([k, v]) => {
          const [keyType, valType] = Object.hasOwn(mapTypeSpec, k) ? mapTypeSpec[k] ?? [null, null] : [null, null];
          const keyOpts = keyType ? { type: keyType } : {};
          const valOpts = valType ? { type: valType } : {};
          return new curr_generated.default.ScMapEntry({
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
          if (bigintVal < BigInt(curr_generated.default.Uint32.MIN_VALUE) || bigintVal > BigInt(curr_generated.default.Uint32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type u32`);
          }
          return curr_generated.default.ScVal.scvU32(Number(val));
        case "i32":
          if (bigintVal < -BigInt(curr_generated.default.Int32.MIN_VALUE) || bigintVal > BigInt(curr_generated.default.Int32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type i32`);
          }
          return curr_generated.default.ScVal.scvI32(Number(val));
      }
      return new sc_int.ScInt(val, { type: opts?.type }).toScVal();
    }
    case "string": {
      const optType = opts?.type ?? "string";
      switch (optType) {
        case "string":
          return curr_generated.default.ScVal.scvString(val);
        case "symbol":
          return curr_generated.default.ScVal.scvSymbol(val);
        case "address":
          return new address.Address(val).toScVal();
        case "u32": {
          const bigintVal = BigInt(val);
          if (bigintVal < BigInt(curr_generated.default.Uint32.MIN_VALUE) || bigintVal > BigInt(curr_generated.default.Uint32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type u32`);
          }
          return curr_generated.default.ScVal.scvU32(Number(bigintVal));
        }
        case "i32": {
          const bigintVal = BigInt(val);
          if (bigintVal < -BigInt(curr_generated.default.Int32.MIN_VALUE) || bigintVal > BigInt(curr_generated.default.Int32.MAX_VALUE)) {
            throw new TypeError(`invalid value (${val}) for type i32`);
          }
          return curr_generated.default.ScVal.scvI32(Number(bigintVal));
        }
        default:
          if (xdr_large_int.XdrLargeInt.isType(optType)) {
            return new xdr_large_int.XdrLargeInt(optType, val).toScVal();
          }
          throw new TypeError(
            `invalid type (${JSON.stringify(opts.type)}) specified for string value`
          );
      }
    }
    case "boolean":
      return curr_generated.default.ScVal.scvBool(val);
    case "undefined":
      return curr_generated.default.ScVal.scvVoid();
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
    case curr_generated.default.ScValType.scvVoid().value:
      return null;
    // these can be converted to bigints directly
    case curr_generated.default.ScValType.scvU64().value:
    case curr_generated.default.ScValType.scvI64().value:
      return scv.value().toBigInt();
    // these can be parsed by internal abstractions note that this can also
    // handle the above two cases, but it's not as efficient (another
    // type-check, parsing, etc.)
    case curr_generated.default.ScValType.scvU128().value:
    case curr_generated.default.ScValType.scvI128().value:
    case curr_generated.default.ScValType.scvU256().value:
    case curr_generated.default.ScValType.scvI256().value:
      return index.scValToBigInt(scv);
    case curr_generated.default.ScValType.scvVec().value:
      return (scv.vec() ?? []).map(scValToNative);
    case curr_generated.default.ScValType.scvAddress().value:
      return address.Address.fromScVal(scv).toString();
    case curr_generated.default.ScValType.scvMap().value:
      return Object.fromEntries(
        (scv.map() ?? []).map((entry) => [
          scValToNative(entry.key()),
          scValToNative(entry.val())
        ])
      );
    // these return the primitive type directly
    case curr_generated.default.ScValType.scvBool().value:
    case curr_generated.default.ScValType.scvU32().value:
    case curr_generated.default.ScValType.scvI32().value:
    case curr_generated.default.ScValType.scvBytes().value:
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
    case curr_generated.default.ScValType.scvSymbol().value: {
      const v = scv.sym();
      if (buffer.Buffer.isBuffer(v) || ArrayBuffer.isView(v) && typeof v !== "string") {
        try {
          return new TextDecoder().decode(v);
        } catch {
          return new Uint8Array(v.buffer);
        }
      }
      return v;
    }
    case curr_generated.default.ScValType.scvString().value: {
      const v = scv.str();
      if (buffer.Buffer.isBuffer(v) || ArrayBuffer.isView(v) && typeof v !== "string") {
        try {
          return new TextDecoder().decode(v);
        } catch {
          return new Uint8Array(v.buffer);
        }
      }
      return v;
    }
    // these can be converted to bigint
    case curr_generated.default.ScValType.scvTimepoint().value:
    case curr_generated.default.ScValType.scvDuration().value:
      return scv.value().toBigInt();
    case curr_generated.default.ScValType.scvError().value:
      switch (scv.error().switch().value) {
        // Distinguish errors from the user contract.
        case curr_generated.default.ScErrorType.sceContract().value:
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
  return curr_generated.default.ScVal.scvMap(sorted);
}
curr_generated.default.scvSortedMap = scvSortedMap;

exports.nativeToScVal = nativeToScVal;
exports.scValToNative = scValToNative;
exports.scvSortedMap = scvSortedMap;
//# sourceMappingURL=scval.js.map

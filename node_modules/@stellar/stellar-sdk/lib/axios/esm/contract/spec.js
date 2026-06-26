import { Buffer } from 'buffer';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import types from '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import { Address } from '../base/address.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import { Contract } from '../base/contract.js';
import '../base/scval.js';
import { scValToBigInt } from '../base/numbers/index.js';
import { Err, Ok } from './rust_result.js';
import { processSpecEntryStream } from './utils.js';
import { specFromWasm } from './wasm_spec_parser.js';
import { XdrLargeInt } from '../base/numbers/xdr_large_int.js';

function enumToJsonSchema(udt) {
  const description = udt.doc().toString();
  const cases = udt.cases();
  const oneOf = [];
  cases.forEach((aCase) => {
    const title = aCase.name().toString();
    const desc = aCase.doc().toString();
    oneOf.push({
      description: desc,
      title,
      enum: [aCase.value()],
      type: "number"
    });
  });
  const res = { oneOf };
  if (description.length > 0) {
    res.description = description;
  }
  return res;
}
function isNumeric(field) {
  return /^\d+$/.test(field.name().toString());
}
function readObj(args, input) {
  const inputName = input.name().toString();
  const entry = Object.entries(args).find(([name]) => name === inputName);
  if (!entry) {
    throw new Error(`Missing field ${inputName}`);
  }
  return entry[1];
}
function findCase(name) {
  return function matches(entry) {
    switch (entry.switch().value) {
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value: {
        const tuple = entry.tupleCase();
        return tuple.name().toString() === name;
      }
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0().value: {
        const voidCase = entry.voidCase();
        return voidCase.name().toString() === name;
      }
      default:
        return false;
    }
  };
}
function stringToScVal(str, ty) {
  switch (ty.value) {
    case types.ScSpecType.scSpecTypeString().value:
      return types.ScVal.scvString(str);
    case types.ScSpecType.scSpecTypeSymbol().value:
      return types.ScVal.scvSymbol(str);
    case types.ScSpecType.scSpecTypeAddress().value:
    case types.ScSpecType.scSpecTypeMuxedAddress().value:
      return Address.fromString(str).toScVal();
    case types.ScSpecType.scSpecTypeU64().value:
      return new XdrLargeInt("u64", str).toScVal();
    case types.ScSpecType.scSpecTypeI64().value:
      return new XdrLargeInt("i64", str).toScVal();
    case types.ScSpecType.scSpecTypeU128().value:
      return new XdrLargeInt("u128", str).toScVal();
    case types.ScSpecType.scSpecTypeI128().value:
      return new XdrLargeInt("i128", str).toScVal();
    case types.ScSpecType.scSpecTypeU256().value:
      return new XdrLargeInt("u256", str).toScVal();
    case types.ScSpecType.scSpecTypeI256().value:
      return new XdrLargeInt("i256", str).toScVal();
    case types.ScSpecType.scSpecTypeBytes().value:
    case types.ScSpecType.scSpecTypeBytesN().value:
      return types.ScVal.scvBytes(Buffer.from(str, "base64"));
    case types.ScSpecType.scSpecTypeTimepoint().value: {
      return types.ScVal.scvTimepoint(new types.Uint64(str));
    }
    case types.ScSpecType.scSpecTypeDuration().value: {
      return types.ScVal.scvDuration(new types.Uint64(str));
    }
    default:
      throw new TypeError(`invalid type ${ty.name} specified for string value`);
  }
}
const PRIMITIVE_DEFINITONS = {
  U32: {
    type: "integer",
    minimum: 0,
    maximum: 4294967295
  },
  I32: {
    type: "integer",
    minimum: -2147483648,
    maximum: 2147483647
  },
  U64: {
    type: "string",
    pattern: "^([1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 20
    // 64-bit max value has 20 digits
  },
  Timepoint: {
    type: "string",
    pattern: "^([1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 20
    // 64-bit max value has 20 digits
  },
  Duration: {
    type: "string",
    pattern: "^([1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 20
    // 64-bit max value has 20 digits
  },
  I64: {
    type: "string",
    pattern: "^(-?[1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 21
    // Includes additional digit for the potential '-'
  },
  U128: {
    type: "string",
    pattern: "^([1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 39
    // 128-bit max value has 39 digits
  },
  I128: {
    type: "string",
    pattern: "^(-?[1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 40
    // Includes additional digit for the potential '-'
  },
  U256: {
    type: "string",
    pattern: "^([1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 78
    // 256-bit max value has 78 digits
  },
  I256: {
    type: "string",
    pattern: "^(-?[1-9][0-9]*|0)$",
    minLength: 1,
    maxLength: 79
    // Includes additional digit for the potential '-'
  },
  Address: {
    type: "string",
    format: "address",
    description: "Address can be a public key or contract id"
  },
  MuxedAddress: {
    type: "string",
    format: "address",
    description: "Stellar public key with M prefix combining a G address and unique ID"
  },
  ScString: {
    type: "string",
    description: "ScString is a string"
  },
  ScSymbol: {
    type: "string",
    description: "ScSymbol is a string"
  },
  DataUrl: {
    type: "string",
    pattern: "^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?$"
  }
};
function typeRef(typeDef) {
  const t = typeDef.switch();
  const value = t.value;
  let ref;
  switch (value) {
    case types.ScSpecType.scSpecTypeVal().value: {
      ref = "Val";
      break;
    }
    case types.ScSpecType.scSpecTypeBool().value: {
      return { type: "boolean" };
    }
    case types.ScSpecType.scSpecTypeVoid().value: {
      return { type: "null" };
    }
    case types.ScSpecType.scSpecTypeError().value: {
      ref = "Error";
      break;
    }
    case types.ScSpecType.scSpecTypeU32().value: {
      ref = "U32";
      break;
    }
    case types.ScSpecType.scSpecTypeI32().value: {
      ref = "I32";
      break;
    }
    case types.ScSpecType.scSpecTypeU64().value: {
      ref = "U64";
      break;
    }
    case types.ScSpecType.scSpecTypeI64().value: {
      ref = "I64";
      break;
    }
    case types.ScSpecType.scSpecTypeTimepoint().value: {
      ref = "Timepoint";
      break;
    }
    case types.ScSpecType.scSpecTypeDuration().value: {
      ref = "Duration";
      break;
    }
    case types.ScSpecType.scSpecTypeU128().value: {
      ref = "U128";
      break;
    }
    case types.ScSpecType.scSpecTypeI128().value: {
      ref = "I128";
      break;
    }
    case types.ScSpecType.scSpecTypeU256().value: {
      ref = "U256";
      break;
    }
    case types.ScSpecType.scSpecTypeI256().value: {
      ref = "I256";
      break;
    }
    case types.ScSpecType.scSpecTypeBytes().value: {
      ref = "DataUrl";
      break;
    }
    case types.ScSpecType.scSpecTypeString().value: {
      ref = "ScString";
      break;
    }
    case types.ScSpecType.scSpecTypeSymbol().value: {
      ref = "ScSymbol";
      break;
    }
    case types.ScSpecType.scSpecTypeAddress().value: {
      ref = "Address";
      break;
    }
    case types.ScSpecType.scSpecTypeMuxedAddress().value: {
      ref = "MuxedAddress";
      break;
    }
    case types.ScSpecType.scSpecTypeOption().value: {
      const opt = typeDef.option();
      return typeRef(opt.valueType());
    }
    case types.ScSpecType.scSpecTypeResult().value: {
      const result = typeDef.result();
      return typeRef(result.okType());
    }
    case types.ScSpecType.scSpecTypeVec().value: {
      const arr = typeDef.vec();
      const reference = typeRef(arr.elementType());
      return {
        type: "array",
        items: reference
      };
    }
    case types.ScSpecType.scSpecTypeMap().value: {
      const map = typeDef.map();
      const items = [typeRef(map.keyType()), typeRef(map.valueType())];
      return {
        type: "array",
        items: {
          type: "array",
          items,
          minItems: 2,
          maxItems: 2
        }
      };
    }
    case types.ScSpecType.scSpecTypeTuple().value: {
      const tuple = typeDef.tuple();
      const minItems = tuple.valueTypes().length;
      const maxItems = minItems;
      const items = tuple.valueTypes().map(typeRef);
      return { type: "array", items, minItems, maxItems };
    }
    case types.ScSpecType.scSpecTypeBytesN().value: {
      const arr = typeDef.bytesN();
      return {
        $ref: "#/definitions/DataUrl",
        maxLength: arr.n()
      };
    }
    case types.ScSpecType.scSpecTypeUdt().value: {
      const udt = typeDef.udt();
      ref = udt.name().toString();
      break;
    }
  }
  return { $ref: `#/definitions/${ref}` };
}
function isRequired(typeDef) {
  return typeDef.switch().value !== types.ScSpecType.scSpecTypeOption().value;
}
function argsAndRequired(input) {
  const properties = {};
  const required = [];
  input.forEach((arg) => {
    const aType = arg.type();
    const name = arg.name().toString();
    properties[name] = typeRef(aType);
    if (isRequired(aType)) {
      required.push(name);
    }
  });
  const res = { properties };
  if (required.length > 0) {
    res.required = required;
  }
  return res;
}
function structToJsonSchema(udt) {
  const fields = udt.fields();
  if (fields.some(isNumeric)) {
    if (!fields.every(isNumeric)) {
      throw new Error(
        "mixed numeric and non-numeric field names are not allowed"
      );
    }
    const items = fields.map((_, i) => typeRef(fields[i].type()));
    return {
      type: "array",
      items,
      minItems: fields.length,
      maxItems: fields.length
    };
  }
  const description = udt.doc().toString();
  const { properties, required } = argsAndRequired(fields);
  return {
    description,
    properties,
    required,
    additionalProperties: false,
    type: "object"
  };
}
function functionToJsonSchema(func) {
  const { properties, required } = argsAndRequired(func.inputs());
  const args = {
    additionalProperties: false,
    properties,
    type: "object"
  };
  if (required?.length > 0) {
    args.required = required;
  }
  const input = {
    properties: {
      args
    }
  };
  const outputs = func.outputs();
  const output = outputs.length > 0 ? typeRef(outputs[0]) : typeRef(types.ScSpecTypeDef.scSpecTypeVoid());
  const description = func.doc().toString();
  if (description.length > 0) {
    input.description = description;
  }
  input.additionalProperties = false;
  output.additionalProperties = false;
  return {
    input,
    output
  };
}
function unionToJsonSchema(udt) {
  const description = udt.doc().toString();
  const cases = udt.cases();
  const oneOf = [];
  cases.forEach((aCase) => {
    switch (aCase.switch().value) {
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0().value: {
        const c = aCase.voidCase();
        const title = c.name().toString();
        oneOf.push({
          type: "object",
          title,
          properties: {
            tag: title
          },
          additionalProperties: false,
          required: ["tag"]
        });
        break;
      }
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value: {
        const c = aCase.tupleCase();
        const title = c.name().toString();
        oneOf.push({
          type: "object",
          title,
          properties: {
            tag: title,
            values: {
              type: "array",
              items: c.type().map(typeRef)
            }
          },
          required: ["tag", "values"],
          additionalProperties: false
        });
      }
    }
  });
  const res = {
    oneOf
  };
  if (description.length > 0) {
    res.description = description;
  }
  return res;
}
class Spec {
  /**
   * The XDR spec entries.
   */
  entries = [];
  /**
   * Generates a Spec instance from the contract's wasm binary.
   *
   * @param wasm - The contract's wasm binary as a Buffer.
   * @returns A Promise that resolves to a Spec instance.
   * @throws If the contract spec cannot be obtained from the provided wasm binary.
   */
  static fromWasm(wasm) {
    const spec = specFromWasm(wasm);
    return new Spec(spec);
  }
  /**
   * Generates a Spec instance from contract specs in any of the following forms:
   * - An XDR encoded stream of xdr.ScSpecEntry entries, the format of the spec
   *   stored inside Wasm files.
   * - A base64 XDR encoded stream of xdr.ScSpecEntry entries.
   * - An array of xdr.ScSpecEntry.
   * - An array of base64 XDR encoded xdr.ScSpecEntry.
   *
   * @returns A Promise that resolves to a Client instance.
   * @throws If the contract spec cannot be obtained from the provided wasm binary.
   */
  constructor(entries) {
    if (Buffer.isBuffer(entries)) {
      this.entries = processSpecEntryStream(entries);
    } else if (typeof entries === "string") {
      this.entries = processSpecEntryStream(Buffer.from(entries, "base64"));
    } else {
      if (entries.length === 0) {
        throw new Error("Contract spec must have at least one entry");
      }
      const entry = entries[0];
      if (typeof entry === "string") {
        this.entries = entries.map(
          (s) => types.ScSpecEntry.fromXDR(s, "base64")
        );
      } else {
        this.entries = entries;
      }
    }
  }
  /**
   * Gets the XDR functions from the spec.
   * @returns all contract functions
   */
  funcs() {
    return this.entries.filter(
      (entry) => entry.switch().value === types.ScSpecEntryKind.scSpecEntryFunctionV0().value
    ).map((entry) => entry.functionV0());
  }
  /**
   * Gets the XDR function spec for the given function name.
   *
   * @param name - the name of the function
   * @returns the function spec
   *
   * @throws if no function with the given name exists
   */
  getFunc(name) {
    const entry = this.findEntry(name);
    if (entry.switch().value !== types.ScSpecEntryKind.scSpecEntryFunctionV0().value) {
      throw new Error(`${name} is not a function`);
    }
    return entry.functionV0();
  }
  /**
   * Converts native JS arguments to ScVals for calling a contract function.
   *
   * @param name - the name of the function
   * @param args - the arguments object
   * @returns the converted arguments
   *
   * @throws if argument is missing or incorrect type
   *
   * @example
   * ```ts
   * const args = {
   *   arg1: 'value1',
   *   arg2: 1234
   * };
   * const scArgs = contractSpec.funcArgsToScVals('funcName', args);
   * ```
   */
  funcArgsToScVals(name, args) {
    const fn = this.getFunc(name);
    return fn.inputs().map((input) => this.nativeToScVal(readObj(args, input), input.type()));
  }
  /**
   * Converts the result ScVal of a function call to a native JS value.
   *
   * @param name - the name of the function
   * @param val_or_base64 - the result ScVal or base64 encoded string
   * @returns the converted native value
   *
   * @throws if return type mismatch or invalid input
   *
   * @example
   * ```ts
   * const resultScv = 'AAA=='; // Base64 encoded ScVal
   * const result = contractSpec.funcResToNative('funcName', resultScv);
   * ```
   */
  funcResToNative(name, val_or_base64) {
    const val = typeof val_or_base64 === "string" ? types.ScVal.fromXDR(val_or_base64, "base64") : val_or_base64;
    const func = this.getFunc(name);
    const outputs = func.outputs();
    if (outputs.length === 0) {
      const type = val.switch();
      if (type.value !== types.ScValType.scvVoid().value) {
        throw new Error(`Expected void, got ${type.name}`);
      }
      return null;
    }
    if (outputs.length > 1) {
      throw new Error(`Multiple outputs not supported`);
    }
    const output = outputs[0];
    if (output.switch().value === types.ScSpecType.scSpecTypeResult().value) {
      if (val.switch().value === types.ScValType.scvError().value) {
        return new Err({ message: val.error().toXDR("base64") });
      }
      return new Ok(this.scValToNative(val, output.result().okType()));
    }
    return this.scValToNative(val, output);
  }
  /**
   * Finds the XDR spec entry for the given name.
   *
   * @param name - the name to find
   * @returns the entry
   *
   * @throws if no entry with the given name exists
   */
  findEntry(name) {
    const entry = this.entries.find(
      (e) => e.value().name().toString() === name
    );
    if (!entry) {
      throw new Error(`no such entry: ${name}`);
    }
    return entry;
  }
  /**
   * Converts a native JS value to an ScVal based on the given type.
   *
   * @param val - the native JS value
   * @param ty - (optional) the expected type
   * @returns the converted ScVal
   *
   * @throws if value cannot be converted to the given type
   */
  nativeToScVal(val, ty) {
    const t = ty.switch();
    const value = t.value;
    if (t.value === types.ScSpecType.scSpecTypeUdt().value) {
      const udt = ty.udt();
      return this.nativeToUdt(val, udt.name().toString());
    }
    if (value === types.ScSpecType.scSpecTypeOption().value) {
      const opt = ty.option();
      if (val === null || val === void 0) {
        return types.ScVal.scvVoid();
      }
      return this.nativeToScVal(val, opt.valueType());
    }
    switch (typeof val) {
      case "object": {
        if (val === null) {
          switch (value) {
            case types.ScSpecType.scSpecTypeVoid().value:
              return types.ScVal.scvVoid();
            default:
              throw new TypeError(
                `Type ${ty} was not void, but value was null`
              );
          }
        }
        if (val instanceof types.ScVal) {
          return val;
        }
        if (val instanceof Address) {
          if (ty.switch().value !== types.ScSpecType.scSpecTypeAddress().value) {
            throw new TypeError(
              `Type ${ty} was not address, but value was Address`
            );
          }
          return val.toScVal();
        }
        if (val instanceof Contract) {
          if (ty.switch().value !== types.ScSpecType.scSpecTypeAddress().value) {
            throw new TypeError(
              `Type ${ty} was not address, but value was Address`
            );
          }
          return val.address().toScVal();
        }
        if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
          const copy = Uint8Array.from(val);
          switch (value) {
            case types.ScSpecType.scSpecTypeBytesN().value: {
              const bytesN = ty.bytesN();
              if (copy.length !== bytesN.n()) {
                throw new TypeError(
                  `expected ${bytesN.n()} bytes, but got ${copy.length}`
                );
              }
              return types.ScVal.scvBytes(copy);
            }
            case types.ScSpecType.scSpecTypeBytes().value:
              return types.ScVal.scvBytes(copy);
            default:
              throw new TypeError(
                `invalid type (${ty}) specified for Bytes and BytesN`
              );
          }
        }
        if (Array.isArray(val)) {
          switch (value) {
            case types.ScSpecType.scSpecTypeVec().value: {
              const vec = ty.vec();
              const elementType = vec.elementType();
              return types.ScVal.scvVec(
                val.map((v) => this.nativeToScVal(v, elementType))
              );
            }
            case types.ScSpecType.scSpecTypeTuple().value: {
              const tup = ty.tuple();
              const valTypes = tup.valueTypes();
              if (val.length !== valTypes.length) {
                throw new TypeError(
                  `Tuple expects ${valTypes.length} values, but ${val.length} were provided`
                );
              }
              return types.ScVal.scvVec(
                val.map((v, i) => this.nativeToScVal(v, valTypes[i]))
              );
            }
            case types.ScSpecType.scSpecTypeMap().value: {
              const map = ty.map();
              const keyType = map.keyType();
              const valueType = map.valueType();
              return types.ScVal.scvMap(
                val.map((entry) => {
                  const key = this.nativeToScVal(entry[0], keyType);
                  const mapVal = this.nativeToScVal(entry[1], valueType);
                  return new types.ScMapEntry({ key, val: mapVal });
                })
              );
            }
            default:
              throw new TypeError(
                `Type ${ty} was not vec, but value was Array`
              );
          }
        }
        if (val.constructor === Map) {
          if (value !== types.ScSpecType.scSpecTypeMap().value) {
            throw new TypeError(`Type ${ty} was not map, but value was Map`);
          }
          const scMap = ty.map();
          const map = val;
          const entries = [];
          const values = map.entries();
          let res = values.next();
          while (!res.done) {
            const [k, v] = res.value;
            const key = this.nativeToScVal(k, scMap.keyType());
            const mapval = this.nativeToScVal(v, scMap.valueType());
            entries.push(new types.ScMapEntry({ key, val: mapval }));
            res = values.next();
          }
          return types.ScVal.scvMap(entries);
        }
        if ((val.constructor?.name ?? "") !== "Object") {
          throw new TypeError(
            `cannot interpret ${val.constructor?.name} value as ScVal (${JSON.stringify(val)})`
          );
        }
        throw new TypeError(
          `Received object ${val}  did not match the provided type ${ty}`
        );
      }
      case "number":
      case "bigint": {
        switch (value) {
          case types.ScSpecType.scSpecTypeU32().value:
            if (BigInt(val) < BigInt(types.Uint32.MIN_VALUE) || BigInt(val) > BigInt(types.Uint32.MAX_VALUE)) {
              throw new RangeError(`Value ${val} is out of range for U32`);
            }
            return types.ScVal.scvU32(Number(val));
          case types.ScSpecType.scSpecTypeI32().value:
            if (
              // TODO: remove the `-` cast on the min value once js-xdr fixes the issue where it treats the min value as unsigned
              BigInt(val) < -BigInt(types.Int32.MIN_VALUE) || BigInt(val) > BigInt(types.Int32.MAX_VALUE)
            ) {
              throw new RangeError(`Value ${val} is out of range for I32`);
            }
            return types.ScVal.scvI32(Number(val));
          case types.ScSpecType.scSpecTypeU64().value:
          case types.ScSpecType.scSpecTypeI64().value:
          case types.ScSpecType.scSpecTypeU128().value:
          case types.ScSpecType.scSpecTypeI128().value:
          case types.ScSpecType.scSpecTypeU256().value:
          case types.ScSpecType.scSpecTypeI256().value:
          case types.ScSpecType.scSpecTypeTimepoint().value:
          case types.ScSpecType.scSpecTypeDuration().value: {
            const intType = t.name.substring(10).toLowerCase();
            return new XdrLargeInt(intType, val).toScVal();
          }
          default:
            throw new TypeError(`invalid type (${ty}) specified for integer`);
        }
      }
      case "string":
        return stringToScVal(val, t);
      case "boolean": {
        if (value !== types.ScSpecType.scSpecTypeBool().value) {
          throw TypeError(`Type ${ty} was not bool, but value was bool`);
        }
        return types.ScVal.scvBool(val);
      }
      case "undefined": {
        if (!ty) {
          return types.ScVal.scvVoid();
        }
        switch (value) {
          case types.ScSpecType.scSpecTypeVoid().value:
          case types.ScSpecType.scSpecTypeOption().value:
            return types.ScVal.scvVoid();
          default:
            throw new TypeError(
              `Type ${ty} was not void, but value was undefined`
            );
        }
      }
      case "function":
        return this.nativeToScVal(val(), ty);
      default:
        throw new TypeError(`failed to convert typeof ${typeof val} (${val})`);
    }
  }
  nativeToUdt(val, name) {
    const entry = this.findEntry(name);
    switch (entry.switch()) {
      case types.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        if (typeof val !== "number") {
          throw new TypeError(
            `expected number for enum ${name}, but got ${typeof val}`
          );
        }
        return this.nativeToEnum(val, entry.udtEnumV0());
      case types.ScSpecEntryKind.scSpecEntryUdtStructV0():
        return this.nativeToStruct(val, entry.udtStructV0());
      case types.ScSpecEntryKind.scSpecEntryUdtUnionV0():
        return this.nativeToUnion(val, entry.udtUnionV0());
      default:
        throw new Error(`failed to parse udt ${name}`);
    }
  }
  nativeToUnion(val, union_) {
    const entryName = val.tag;
    const caseFound = union_.cases().find((entry) => {
      const caseN = entry.value().name().toString();
      return caseN === entryName;
    });
    if (!caseFound) {
      throw new TypeError(`no such enum entry: ${entryName} in ${union_}`);
    }
    const key = types.ScVal.scvSymbol(entryName);
    switch (caseFound.switch()) {
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0(): {
        return types.ScVal.scvVec([key]);
      }
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0(): {
        const types$1 = caseFound.tupleCase().type();
        if (Array.isArray(val.values)) {
          if (val.values.length !== types$1.length) {
            throw new TypeError(
              `union ${union_} expects ${types$1.length} values, but got ${val.values.length}`
            );
          }
          const scvals = val.values.map(
            (v, i) => this.nativeToScVal(v, types$1[i])
          );
          scvals.unshift(key);
          return types.ScVal.scvVec(scvals);
        }
        throw new Error(`failed to parse union case ${caseFound} with ${val}`);
      }
      default:
        throw new Error(`failed to parse union ${union_} with ${val}`);
    }
  }
  nativeToStruct(val, struct) {
    const fields = struct.fields();
    if (fields.some(isNumeric)) {
      if (!fields.every(isNumeric)) {
        throw new Error(
          "mixed numeric and non-numeric field names are not allowed"
        );
      }
      return types.ScVal.scvVec(
        fields.map((_, i) => this.nativeToScVal(val[i], fields[i].type()))
      );
    }
    return types.ScVal.scvMap(
      fields.map((field) => {
        const name = field.name().toString();
        return new types.ScMapEntry({
          key: this.nativeToScVal(name, types.ScSpecTypeDef.scSpecTypeSymbol()),
          val: this.nativeToScVal(val[name], field.type())
        });
      })
    );
  }
  nativeToEnum(val, enum_) {
    if (enum_.cases().some((entry) => entry.value() === val)) {
      return types.ScVal.scvU32(val);
    }
    throw new TypeError(`no such enum entry: ${val} in ${enum_}`);
  }
  /**
   * Converts an base64 encoded ScVal back to a native JS value based on the given type.
   *
   * @param scv - the base64 encoded ScVal
   * @param typeDef - the expected type
   * @returns the converted native JS value
   *
   * @throws if ScVal cannot be converted to the given type
   */
  scValStrToNative(scv, typeDef) {
    return this.scValToNative(types.ScVal.fromXDR(scv, "base64"), typeDef);
  }
  /**
   * Converts an ScVal back to a native JS value based on the given type.
   *
   * @param scv - the ScVal
   * @param typeDef - the expected type
   * @returns the converted native JS value
   *
   * @throws if ScVal cannot be converted to the given type
   */
  scValToNative(scv, typeDef) {
    const t = typeDef.switch();
    const value = t.value;
    if (value === types.ScSpecType.scSpecTypeOption().value) {
      switch (scv.switch().value) {
        case types.ScValType.scvVoid().value:
          return null;
        default:
          return this.scValToNative(scv, typeDef.option().valueType());
      }
    }
    if (value === types.ScSpecType.scSpecTypeUdt().value) {
      return this.scValUdtToNative(scv, typeDef.udt());
    }
    switch (scv.switch().value) {
      case types.ScValType.scvVoid().value:
        return null;
      // these can be converted to bigints directly
      case types.ScValType.scvU64().value:
      case types.ScValType.scvI64().value:
      case types.ScValType.scvTimepoint().value:
      case types.ScValType.scvDuration().value:
      // these can be parsed by internal abstractions note that this can also
      // handle the above two cases, but it's not as efficient (another
      // type-check, parsing, etc.)
      case types.ScValType.scvU128().value:
      case types.ScValType.scvI128().value:
      case types.ScValType.scvU256().value:
      case types.ScValType.scvI256().value:
        return scValToBigInt(scv);
      case types.ScValType.scvVec().value: {
        if (value === types.ScSpecType.scSpecTypeVec().value) {
          const vec = typeDef.vec();
          return (scv.vec() ?? []).map(
            (elm) => this.scValToNative(elm, vec.elementType())
          );
        }
        if (value === types.ScSpecType.scSpecTypeTuple().value) {
          const tuple = typeDef.tuple();
          const valTypes = tuple.valueTypes();
          return (scv.vec() ?? []).map(
            (elm, i) => this.scValToNative(elm, valTypes[i])
          );
        }
        throw new TypeError(`Type ${typeDef} was not vec, but ${scv} is`);
      }
      case types.ScValType.scvAddress().value:
        return Address.fromScVal(scv).toString();
      case types.ScValType.scvMap().value: {
        const map = scv.map() ?? [];
        if (value === types.ScSpecType.scSpecTypeMap().value) {
          const typed = typeDef.map();
          const keyType = typed.keyType();
          const valueType = typed.valueType();
          const res = map.map((entry) => [
            this.scValToNative(entry.key(), keyType),
            this.scValToNative(entry.val(), valueType)
          ]);
          return res;
        }
        throw new TypeError(
          `ScSpecType ${t.name} was not map, but ${JSON.stringify(
            scv,
            null,
            2
          )} is`
        );
      }
      // these return the primitive type directly
      case types.ScValType.scvBool().value:
      case types.ScValType.scvU32().value:
      case types.ScValType.scvI32().value:
      case types.ScValType.scvBytes().value:
        return scv.value();
      case types.ScValType.scvString().value:
      case types.ScValType.scvSymbol().value: {
        if (value !== types.ScSpecType.scSpecTypeString().value && value !== types.ScSpecType.scSpecTypeSymbol().value) {
          throw new Error(
            `ScSpecType ${t.name} was not string or symbol, but ${JSON.stringify(scv, null, 2)} is`
          );
        }
        return scv.value()?.toString();
      }
      // in the fallthrough case, just return the underlying value directly
      default:
        throw new TypeError(
          `failed to convert ${JSON.stringify(
            scv,
            null,
            2
          )} to native type from type ${t.name}`
        );
    }
  }
  scValUdtToNative(scv, udt) {
    const entry = this.findEntry(udt.name().toString());
    switch (entry.switch()) {
      case types.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        return this.enumToNative(scv);
      case types.ScSpecEntryKind.scSpecEntryUdtStructV0():
        return this.structToNative(scv, entry.udtStructV0());
      case types.ScSpecEntryKind.scSpecEntryUdtUnionV0():
        return this.unionToNative(scv, entry.udtUnionV0());
      default:
        throw new Error(
          `failed to parse udt ${udt.name().toString()}: ${entry}`
        );
    }
  }
  unionToNative(val, udt) {
    const vec = val.vec();
    if (!vec) {
      throw new Error(`${JSON.stringify(val, null, 2)} is not a vec`);
    }
    if (vec.length === 0 && udt.cases.length !== 0) {
      throw new Error(
        `${val} has length 0, but the there are at least one case in the union`
      );
    }
    const name = vec[0].sym().toString();
    if (vec[0].switch().value !== types.ScValType.scvSymbol().value) {
      throw new Error(`${vec[0]} is not a symbol`);
    }
    const entry = udt.cases().find(findCase(name));
    if (!entry) {
      throw new Error(
        `failed to find entry ${name} in union ${udt.name().toString()}`
      );
    }
    const res = { tag: name };
    if (entry.switch().value === types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value) {
      const tuple = entry.tupleCase();
      const ty = tuple.type();
      const values = ty.map((e, i) => this.scValToNative(vec[i + 1], e));
      res.values = values;
    }
    return res;
  }
  structToNative(val, udt) {
    const res = {};
    const fields = udt.fields();
    if (fields.some(isNumeric)) {
      const r = val.vec()?.map((entry, i) => this.scValToNative(entry, fields[i].type()));
      return r;
    }
    val.map()?.forEach((entry, i) => {
      const field = fields[i];
      res[field.name().toString()] = this.scValToNative(
        entry.val(),
        field.type()
      );
    });
    return res;
  }
  enumToNative(scv) {
    if (scv.switch().value !== types.ScValType.scvU32().value) {
      throw new Error(`Enum must have a u32 value`);
    }
    const num = scv.u32();
    return num;
  }
  /**
   * Gets the XDR error cases from the spec.
   *
   * @returns all contract functions
   *
   */
  errorCases() {
    return this.entries.filter(
      (entry) => entry.switch().value === types.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0().value
    ).flatMap((entry) => entry.value().cases());
  }
  /**
   * Converts the contract spec to a JSON schema.
   *
   * If `funcName` is provided, the schema will be a reference to the function schema.
   *
   * @param funcName - (optional) the name of the function to convert
   * @returns the converted JSON schema
   *
   * @throws if the contract spec is invalid
   */
  jsonSchema(funcName) {
    const definitions = {};
    this.entries.forEach((entry) => {
      switch (entry.switch().value) {
        case types.ScSpecEntryKind.scSpecEntryUdtEnumV0().value: {
          const udt = entry.udtEnumV0();
          definitions[udt.name().toString()] = enumToJsonSchema(udt);
          break;
        }
        case types.ScSpecEntryKind.scSpecEntryUdtStructV0().value: {
          const udt = entry.udtStructV0();
          definitions[udt.name().toString()] = structToJsonSchema(udt);
          break;
        }
        case types.ScSpecEntryKind.scSpecEntryUdtUnionV0().value: {
          const udt = entry.udtUnionV0();
          definitions[udt.name().toString()] = unionToJsonSchema(udt);
          break;
        }
        case types.ScSpecEntryKind.scSpecEntryFunctionV0().value: {
          const fn = entry.functionV0();
          const fnName = fn.name().toString();
          const { input } = functionToJsonSchema(fn);
          definitions[fnName] = input;
          break;
        }
        case types.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0().value:      }
    });
    const res = {
      $schema: "http://json-schema.org/draft-07/schema#",
      definitions: { ...PRIMITIVE_DEFINITONS, ...definitions }
    };
    if (funcName) {
      res.$ref = `#/definitions/${funcName}`;
    }
    return res;
  }
}

export { Spec };
//# sourceMappingURL=spec.js.map

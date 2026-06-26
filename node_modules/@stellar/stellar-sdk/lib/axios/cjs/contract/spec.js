'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
var curr_generated = require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
var address = require('../base/address.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var contract = require('../base/contract.js');
require('../base/scval.js');
var index = require('../base/numbers/index.js');
var rust_result = require('./rust_result.js');
var utils = require('./utils.js');
var wasm_spec_parser = require('./wasm_spec_parser.js');
var xdr_large_int = require('../base/numbers/xdr_large_int.js');

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
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value: {
        const tuple = entry.tupleCase();
        return tuple.name().toString() === name;
      }
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0().value: {
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
    case curr_generated.default.ScSpecType.scSpecTypeString().value:
      return curr_generated.default.ScVal.scvString(str);
    case curr_generated.default.ScSpecType.scSpecTypeSymbol().value:
      return curr_generated.default.ScVal.scvSymbol(str);
    case curr_generated.default.ScSpecType.scSpecTypeAddress().value:
    case curr_generated.default.ScSpecType.scSpecTypeMuxedAddress().value:
      return address.Address.fromString(str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeU64().value:
      return new xdr_large_int.XdrLargeInt("u64", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeI64().value:
      return new xdr_large_int.XdrLargeInt("i64", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeU128().value:
      return new xdr_large_int.XdrLargeInt("u128", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeI128().value:
      return new xdr_large_int.XdrLargeInt("i128", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeU256().value:
      return new xdr_large_int.XdrLargeInt("u256", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeI256().value:
      return new xdr_large_int.XdrLargeInt("i256", str).toScVal();
    case curr_generated.default.ScSpecType.scSpecTypeBytes().value:
    case curr_generated.default.ScSpecType.scSpecTypeBytesN().value:
      return curr_generated.default.ScVal.scvBytes(buffer.Buffer.from(str, "base64"));
    case curr_generated.default.ScSpecType.scSpecTypeTimepoint().value: {
      return curr_generated.default.ScVal.scvTimepoint(new curr_generated.default.Uint64(str));
    }
    case curr_generated.default.ScSpecType.scSpecTypeDuration().value: {
      return curr_generated.default.ScVal.scvDuration(new curr_generated.default.Uint64(str));
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
    case curr_generated.default.ScSpecType.scSpecTypeVal().value: {
      ref = "Val";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeBool().value: {
      return { type: "boolean" };
    }
    case curr_generated.default.ScSpecType.scSpecTypeVoid().value: {
      return { type: "null" };
    }
    case curr_generated.default.ScSpecType.scSpecTypeError().value: {
      ref = "Error";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeU32().value: {
      ref = "U32";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeI32().value: {
      ref = "I32";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeU64().value: {
      ref = "U64";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeI64().value: {
      ref = "I64";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeTimepoint().value: {
      ref = "Timepoint";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeDuration().value: {
      ref = "Duration";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeU128().value: {
      ref = "U128";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeI128().value: {
      ref = "I128";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeU256().value: {
      ref = "U256";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeI256().value: {
      ref = "I256";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeBytes().value: {
      ref = "DataUrl";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeString().value: {
      ref = "ScString";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeSymbol().value: {
      ref = "ScSymbol";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeAddress().value: {
      ref = "Address";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeMuxedAddress().value: {
      ref = "MuxedAddress";
      break;
    }
    case curr_generated.default.ScSpecType.scSpecTypeOption().value: {
      const opt = typeDef.option();
      return typeRef(opt.valueType());
    }
    case curr_generated.default.ScSpecType.scSpecTypeResult().value: {
      const result = typeDef.result();
      return typeRef(result.okType());
    }
    case curr_generated.default.ScSpecType.scSpecTypeVec().value: {
      const arr = typeDef.vec();
      const reference = typeRef(arr.elementType());
      return {
        type: "array",
        items: reference
      };
    }
    case curr_generated.default.ScSpecType.scSpecTypeMap().value: {
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
    case curr_generated.default.ScSpecType.scSpecTypeTuple().value: {
      const tuple = typeDef.tuple();
      const minItems = tuple.valueTypes().length;
      const maxItems = minItems;
      const items = tuple.valueTypes().map(typeRef);
      return { type: "array", items, minItems, maxItems };
    }
    case curr_generated.default.ScSpecType.scSpecTypeBytesN().value: {
      const arr = typeDef.bytesN();
      return {
        $ref: "#/definitions/DataUrl",
        maxLength: arr.n()
      };
    }
    case curr_generated.default.ScSpecType.scSpecTypeUdt().value: {
      const udt = typeDef.udt();
      ref = udt.name().toString();
      break;
    }
  }
  return { $ref: `#/definitions/${ref}` };
}
function isRequired(typeDef) {
  return typeDef.switch().value !== curr_generated.default.ScSpecType.scSpecTypeOption().value;
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
  const output = outputs.length > 0 ? typeRef(outputs[0]) : typeRef(curr_generated.default.ScSpecTypeDef.scSpecTypeVoid());
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
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0().value: {
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
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value: {
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
    const spec = wasm_spec_parser.specFromWasm(wasm);
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
    if (buffer.Buffer.isBuffer(entries)) {
      this.entries = utils.processSpecEntryStream(entries);
    } else if (typeof entries === "string") {
      this.entries = utils.processSpecEntryStream(buffer.Buffer.from(entries, "base64"));
    } else {
      if (entries.length === 0) {
        throw new Error("Contract spec must have at least one entry");
      }
      const entry = entries[0];
      if (typeof entry === "string") {
        this.entries = entries.map(
          (s) => curr_generated.default.ScSpecEntry.fromXDR(s, "base64")
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
      (entry) => entry.switch().value === curr_generated.default.ScSpecEntryKind.scSpecEntryFunctionV0().value
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
    if (entry.switch().value !== curr_generated.default.ScSpecEntryKind.scSpecEntryFunctionV0().value) {
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
    const val = typeof val_or_base64 === "string" ? curr_generated.default.ScVal.fromXDR(val_or_base64, "base64") : val_or_base64;
    const func = this.getFunc(name);
    const outputs = func.outputs();
    if (outputs.length === 0) {
      const type = val.switch();
      if (type.value !== curr_generated.default.ScValType.scvVoid().value) {
        throw new Error(`Expected void, got ${type.name}`);
      }
      return null;
    }
    if (outputs.length > 1) {
      throw new Error(`Multiple outputs not supported`);
    }
    const output = outputs[0];
    if (output.switch().value === curr_generated.default.ScSpecType.scSpecTypeResult().value) {
      if (val.switch().value === curr_generated.default.ScValType.scvError().value) {
        return new rust_result.Err({ message: val.error().toXDR("base64") });
      }
      return new rust_result.Ok(this.scValToNative(val, output.result().okType()));
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
    if (t.value === curr_generated.default.ScSpecType.scSpecTypeUdt().value) {
      const udt = ty.udt();
      return this.nativeToUdt(val, udt.name().toString());
    }
    if (value === curr_generated.default.ScSpecType.scSpecTypeOption().value) {
      const opt = ty.option();
      if (val === null || val === void 0) {
        return curr_generated.default.ScVal.scvVoid();
      }
      return this.nativeToScVal(val, opt.valueType());
    }
    switch (typeof val) {
      case "object": {
        if (val === null) {
          switch (value) {
            case curr_generated.default.ScSpecType.scSpecTypeVoid().value:
              return curr_generated.default.ScVal.scvVoid();
            default:
              throw new TypeError(
                `Type ${ty} was not void, but value was null`
              );
          }
        }
        if (val instanceof curr_generated.default.ScVal) {
          return val;
        }
        if (val instanceof address.Address) {
          if (ty.switch().value !== curr_generated.default.ScSpecType.scSpecTypeAddress().value) {
            throw new TypeError(
              `Type ${ty} was not address, but value was Address`
            );
          }
          return val.toScVal();
        }
        if (val instanceof contract.Contract) {
          if (ty.switch().value !== curr_generated.default.ScSpecType.scSpecTypeAddress().value) {
            throw new TypeError(
              `Type ${ty} was not address, but value was Address`
            );
          }
          return val.address().toScVal();
        }
        if (val instanceof Uint8Array || buffer.Buffer.isBuffer(val)) {
          const copy = Uint8Array.from(val);
          switch (value) {
            case curr_generated.default.ScSpecType.scSpecTypeBytesN().value: {
              const bytesN = ty.bytesN();
              if (copy.length !== bytesN.n()) {
                throw new TypeError(
                  `expected ${bytesN.n()} bytes, but got ${copy.length}`
                );
              }
              return curr_generated.default.ScVal.scvBytes(copy);
            }
            case curr_generated.default.ScSpecType.scSpecTypeBytes().value:
              return curr_generated.default.ScVal.scvBytes(copy);
            default:
              throw new TypeError(
                `invalid type (${ty}) specified for Bytes and BytesN`
              );
          }
        }
        if (Array.isArray(val)) {
          switch (value) {
            case curr_generated.default.ScSpecType.scSpecTypeVec().value: {
              const vec = ty.vec();
              const elementType = vec.elementType();
              return curr_generated.default.ScVal.scvVec(
                val.map((v) => this.nativeToScVal(v, elementType))
              );
            }
            case curr_generated.default.ScSpecType.scSpecTypeTuple().value: {
              const tup = ty.tuple();
              const valTypes = tup.valueTypes();
              if (val.length !== valTypes.length) {
                throw new TypeError(
                  `Tuple expects ${valTypes.length} values, but ${val.length} were provided`
                );
              }
              return curr_generated.default.ScVal.scvVec(
                val.map((v, i) => this.nativeToScVal(v, valTypes[i]))
              );
            }
            case curr_generated.default.ScSpecType.scSpecTypeMap().value: {
              const map = ty.map();
              const keyType = map.keyType();
              const valueType = map.valueType();
              return curr_generated.default.ScVal.scvMap(
                val.map((entry) => {
                  const key = this.nativeToScVal(entry[0], keyType);
                  const mapVal = this.nativeToScVal(entry[1], valueType);
                  return new curr_generated.default.ScMapEntry({ key, val: mapVal });
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
          if (value !== curr_generated.default.ScSpecType.scSpecTypeMap().value) {
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
            entries.push(new curr_generated.default.ScMapEntry({ key, val: mapval }));
            res = values.next();
          }
          return curr_generated.default.ScVal.scvMap(entries);
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
          case curr_generated.default.ScSpecType.scSpecTypeU32().value:
            if (BigInt(val) < BigInt(curr_generated.default.Uint32.MIN_VALUE) || BigInt(val) > BigInt(curr_generated.default.Uint32.MAX_VALUE)) {
              throw new RangeError(`Value ${val} is out of range for U32`);
            }
            return curr_generated.default.ScVal.scvU32(Number(val));
          case curr_generated.default.ScSpecType.scSpecTypeI32().value:
            if (
              // TODO: remove the `-` cast on the min value once js-xdr fixes the issue where it treats the min value as unsigned
              BigInt(val) < -BigInt(curr_generated.default.Int32.MIN_VALUE) || BigInt(val) > BigInt(curr_generated.default.Int32.MAX_VALUE)
            ) {
              throw new RangeError(`Value ${val} is out of range for I32`);
            }
            return curr_generated.default.ScVal.scvI32(Number(val));
          case curr_generated.default.ScSpecType.scSpecTypeU64().value:
          case curr_generated.default.ScSpecType.scSpecTypeI64().value:
          case curr_generated.default.ScSpecType.scSpecTypeU128().value:
          case curr_generated.default.ScSpecType.scSpecTypeI128().value:
          case curr_generated.default.ScSpecType.scSpecTypeU256().value:
          case curr_generated.default.ScSpecType.scSpecTypeI256().value:
          case curr_generated.default.ScSpecType.scSpecTypeTimepoint().value:
          case curr_generated.default.ScSpecType.scSpecTypeDuration().value: {
            const intType = t.name.substring(10).toLowerCase();
            return new xdr_large_int.XdrLargeInt(intType, val).toScVal();
          }
          default:
            throw new TypeError(`invalid type (${ty}) specified for integer`);
        }
      }
      case "string":
        return stringToScVal(val, t);
      case "boolean": {
        if (value !== curr_generated.default.ScSpecType.scSpecTypeBool().value) {
          throw TypeError(`Type ${ty} was not bool, but value was bool`);
        }
        return curr_generated.default.ScVal.scvBool(val);
      }
      case "undefined": {
        if (!ty) {
          return curr_generated.default.ScVal.scvVoid();
        }
        switch (value) {
          case curr_generated.default.ScSpecType.scSpecTypeVoid().value:
          case curr_generated.default.ScSpecType.scSpecTypeOption().value:
            return curr_generated.default.ScVal.scvVoid();
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
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        if (typeof val !== "number") {
          throw new TypeError(
            `expected number for enum ${name}, but got ${typeof val}`
          );
        }
        return this.nativeToEnum(val, entry.udtEnumV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtStructV0():
        return this.nativeToStruct(val, entry.udtStructV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtUnionV0():
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
    const key = curr_generated.default.ScVal.scvSymbol(entryName);
    switch (caseFound.switch()) {
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0(): {
        return curr_generated.default.ScVal.scvVec([key]);
      }
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0(): {
        const types = caseFound.tupleCase().type();
        if (Array.isArray(val.values)) {
          if (val.values.length !== types.length) {
            throw new TypeError(
              `union ${union_} expects ${types.length} values, but got ${val.values.length}`
            );
          }
          const scvals = val.values.map(
            (v, i) => this.nativeToScVal(v, types[i])
          );
          scvals.unshift(key);
          return curr_generated.default.ScVal.scvVec(scvals);
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
      return curr_generated.default.ScVal.scvVec(
        fields.map((_, i) => this.nativeToScVal(val[i], fields[i].type()))
      );
    }
    return curr_generated.default.ScVal.scvMap(
      fields.map((field) => {
        const name = field.name().toString();
        return new curr_generated.default.ScMapEntry({
          key: this.nativeToScVal(name, curr_generated.default.ScSpecTypeDef.scSpecTypeSymbol()),
          val: this.nativeToScVal(val[name], field.type())
        });
      })
    );
  }
  nativeToEnum(val, enum_) {
    if (enum_.cases().some((entry) => entry.value() === val)) {
      return curr_generated.default.ScVal.scvU32(val);
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
    return this.scValToNative(curr_generated.default.ScVal.fromXDR(scv, "base64"), typeDef);
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
    if (value === curr_generated.default.ScSpecType.scSpecTypeOption().value) {
      switch (scv.switch().value) {
        case curr_generated.default.ScValType.scvVoid().value:
          return null;
        default:
          return this.scValToNative(scv, typeDef.option().valueType());
      }
    }
    if (value === curr_generated.default.ScSpecType.scSpecTypeUdt().value) {
      return this.scValUdtToNative(scv, typeDef.udt());
    }
    switch (scv.switch().value) {
      case curr_generated.default.ScValType.scvVoid().value:
        return null;
      // these can be converted to bigints directly
      case curr_generated.default.ScValType.scvU64().value:
      case curr_generated.default.ScValType.scvI64().value:
      case curr_generated.default.ScValType.scvTimepoint().value:
      case curr_generated.default.ScValType.scvDuration().value:
      // these can be parsed by internal abstractions note that this can also
      // handle the above two cases, but it's not as efficient (another
      // type-check, parsing, etc.)
      case curr_generated.default.ScValType.scvU128().value:
      case curr_generated.default.ScValType.scvI128().value:
      case curr_generated.default.ScValType.scvU256().value:
      case curr_generated.default.ScValType.scvI256().value:
        return index.scValToBigInt(scv);
      case curr_generated.default.ScValType.scvVec().value: {
        if (value === curr_generated.default.ScSpecType.scSpecTypeVec().value) {
          const vec = typeDef.vec();
          return (scv.vec() ?? []).map(
            (elm) => this.scValToNative(elm, vec.elementType())
          );
        }
        if (value === curr_generated.default.ScSpecType.scSpecTypeTuple().value) {
          const tuple = typeDef.tuple();
          const valTypes = tuple.valueTypes();
          return (scv.vec() ?? []).map(
            (elm, i) => this.scValToNative(elm, valTypes[i])
          );
        }
        throw new TypeError(`Type ${typeDef} was not vec, but ${scv} is`);
      }
      case curr_generated.default.ScValType.scvAddress().value:
        return address.Address.fromScVal(scv).toString();
      case curr_generated.default.ScValType.scvMap().value: {
        const map = scv.map() ?? [];
        if (value === curr_generated.default.ScSpecType.scSpecTypeMap().value) {
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
      case curr_generated.default.ScValType.scvBool().value:
      case curr_generated.default.ScValType.scvU32().value:
      case curr_generated.default.ScValType.scvI32().value:
      case curr_generated.default.ScValType.scvBytes().value:
        return scv.value();
      case curr_generated.default.ScValType.scvString().value:
      case curr_generated.default.ScValType.scvSymbol().value: {
        if (value !== curr_generated.default.ScSpecType.scSpecTypeString().value && value !== curr_generated.default.ScSpecType.scSpecTypeSymbol().value) {
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
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        return this.enumToNative(scv);
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtStructV0():
        return this.structToNative(scv, entry.udtStructV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtUnionV0():
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
    if (vec[0].switch().value !== curr_generated.default.ScValType.scvSymbol().value) {
      throw new Error(`${vec[0]} is not a symbol`);
    }
    const entry = udt.cases().find(findCase(name));
    if (!entry) {
      throw new Error(
        `failed to find entry ${name} in union ${udt.name().toString()}`
      );
    }
    const res = { tag: name };
    if (entry.switch().value === curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0().value) {
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
    if (scv.switch().value !== curr_generated.default.ScValType.scvU32().value) {
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
      (entry) => entry.switch().value === curr_generated.default.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0().value
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
        case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtEnumV0().value: {
          const udt = entry.udtEnumV0();
          definitions[udt.name().toString()] = enumToJsonSchema(udt);
          break;
        }
        case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtStructV0().value: {
          const udt = entry.udtStructV0();
          definitions[udt.name().toString()] = structToJsonSchema(udt);
          break;
        }
        case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtUnionV0().value: {
          const udt = entry.udtUnionV0();
          definitions[udt.name().toString()] = unionToJsonSchema(udt);
          break;
        }
        case curr_generated.default.ScSpecEntryKind.scSpecEntryFunctionV0().value: {
          const fn = entry.functionV0();
          const fnName = fn.name().toString();
          const { input } = functionToJsonSchema(fn);
          definitions[fnName] = input;
          break;
        }
        case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0().value:      }
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

exports.Spec = Spec;
//# sourceMappingURL=spec.js.map

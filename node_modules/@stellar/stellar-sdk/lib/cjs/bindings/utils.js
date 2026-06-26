'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var curr_generated = require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');

function isNameReserved(name) {
  const reservedNames = [
    // Keywords
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    // Future reserved words
    "enum",
    // Strict mode reserved words
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    // Contextual keywords
    "async",
    "await",
    "constructor",
    // Literals
    "null",
    "true",
    "false"
  ];
  return reservedNames.includes(name);
}
function sanitizeIdentifier(identifier) {
  const sanitized = identifier.replace(/[^a-zA-Z0-9_$]/g, "_");
  if (isNameReserved(sanitized)) {
    return sanitized + "_";
  }
  if (/^\d/.test(sanitized)) {
    return "_" + sanitized;
  }
  if (sanitized === "" || /^_+$/.test(sanitized)) {
    return "_unnamed";
  }
  return sanitized;
}
function escapeStringLiteral(str) {
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
function parseTypeFromTypeDef(typeDef, isFunctionInput = false) {
  switch (typeDef.switch()) {
    case curr_generated.default.ScSpecType.scSpecTypeVal():
      return "any";
    case curr_generated.default.ScSpecType.scSpecTypeBool():
      return "boolean";
    case curr_generated.default.ScSpecType.scSpecTypeVoid():
      return "null";
    case curr_generated.default.ScSpecType.scSpecTypeError():
      return "Error";
    case curr_generated.default.ScSpecType.scSpecTypeU32():
    case curr_generated.default.ScSpecType.scSpecTypeI32():
      return "number";
    case curr_generated.default.ScSpecType.scSpecTypeU64():
    case curr_generated.default.ScSpecType.scSpecTypeI64():
    case curr_generated.default.ScSpecType.scSpecTypeTimepoint():
    case curr_generated.default.ScSpecType.scSpecTypeDuration():
    case curr_generated.default.ScSpecType.scSpecTypeU128():
    case curr_generated.default.ScSpecType.scSpecTypeI128():
    case curr_generated.default.ScSpecType.scSpecTypeU256():
    case curr_generated.default.ScSpecType.scSpecTypeI256():
      return "bigint";
    case curr_generated.default.ScSpecType.scSpecTypeBytes():
    case curr_generated.default.ScSpecType.scSpecTypeBytesN():
      return "Buffer";
    case curr_generated.default.ScSpecType.scSpecTypeString():
      return "string";
    case curr_generated.default.ScSpecType.scSpecTypeSymbol():
      return "string";
    case curr_generated.default.ScSpecType.scSpecTypeAddress():
    case curr_generated.default.ScSpecType.scSpecTypeMuxedAddress(): {
      if (isFunctionInput) {
        return "string | Address";
      }
      return "string";
    }
    case curr_generated.default.ScSpecType.scSpecTypeVec(): {
      const vecType = parseTypeFromTypeDef(
        typeDef.vec().elementType(),
        isFunctionInput
      );
      return `Array<${vecType}>`;
    }
    case curr_generated.default.ScSpecType.scSpecTypeMap(): {
      const keyType = parseTypeFromTypeDef(
        typeDef.map().keyType(),
        isFunctionInput
      );
      const valueType = parseTypeFromTypeDef(
        typeDef.map().valueType(),
        isFunctionInput
      );
      return `Map<${keyType}, ${valueType}>`;
    }
    case curr_generated.default.ScSpecType.scSpecTypeTuple(): {
      const tupleTypes = typeDef.tuple().valueTypes().map(
        (t) => parseTypeFromTypeDef(t, isFunctionInput)
      );
      return `[${tupleTypes.join(", ")}]`;
    }
    case curr_generated.default.ScSpecType.scSpecTypeOption(): {
      while (typeDef.option().valueType().switch() === curr_generated.default.ScSpecType.scSpecTypeOption()) {
        typeDef = typeDef.option().valueType();
      }
      const optionType = parseTypeFromTypeDef(
        typeDef.option().valueType(),
        isFunctionInput
      );
      return `${optionType} | null`;
    }
    case curr_generated.default.ScSpecType.scSpecTypeResult(): {
      const okType = parseTypeFromTypeDef(
        typeDef.result().okType(),
        isFunctionInput
      );
      const errorType = parseTypeFromTypeDef(
        typeDef.result().errorType(),
        isFunctionInput
      );
      return `Result<${okType}, ${errorType}>`;
    }
    case curr_generated.default.ScSpecType.scSpecTypeUdt(): {
      const udtName = sanitizeIdentifier(typeDef.udt().name().toString());
      return udtName;
    }
    default:
      return "unknown";
  }
}
function extractNestedTypes(typeDef) {
  switch (typeDef.switch()) {
    case curr_generated.default.ScSpecType.scSpecTypeVec():
      return [typeDef.vec().elementType()];
    case curr_generated.default.ScSpecType.scSpecTypeMap():
      return [typeDef.map().keyType(), typeDef.map().valueType()];
    case curr_generated.default.ScSpecType.scSpecTypeTuple():
      return typeDef.tuple().valueTypes();
    case curr_generated.default.ScSpecType.scSpecTypeOption():
      return [typeDef.option().valueType()];
    case curr_generated.default.ScSpecType.scSpecTypeResult():
      return [typeDef.result().okType(), typeDef.result().errorType()];
    default:
      return [];
  }
}
function visitTypeDef(typeDef, accumulator) {
  const typeSwitch = typeDef.switch();
  switch (typeSwitch) {
    case curr_generated.default.ScSpecType.scSpecTypeUdt():
      accumulator.typeFileImports.add(
        sanitizeIdentifier(typeDef.udt().name().toString())
      );
      return;
    case curr_generated.default.ScSpecType.scSpecTypeAddress():
    case curr_generated.default.ScSpecType.scSpecTypeMuxedAddress():
      accumulator.stellarImports.add("Address");
      return;
    case curr_generated.default.ScSpecType.scSpecTypeBytes():
    case curr_generated.default.ScSpecType.scSpecTypeBytesN():
      accumulator.needsBufferImport = true;
      return;
    case curr_generated.default.ScSpecType.scSpecTypeVal():
      accumulator.stellarImports.add("xdr");
      return;
    case curr_generated.default.ScSpecType.scSpecTypeResult():
      accumulator.stellarContractImports.add("Result");
      break;
    // Primitive types that need no imports
    case curr_generated.default.ScSpecType.scSpecTypeBool():
    case curr_generated.default.ScSpecType.scSpecTypeVoid():
    case curr_generated.default.ScSpecType.scSpecTypeError():
    case curr_generated.default.ScSpecType.scSpecTypeU32():
    case curr_generated.default.ScSpecType.scSpecTypeI32():
    case curr_generated.default.ScSpecType.scSpecTypeU64():
    case curr_generated.default.ScSpecType.scSpecTypeI64():
    case curr_generated.default.ScSpecType.scSpecTypeTimepoint():
    case curr_generated.default.ScSpecType.scSpecTypeDuration():
    case curr_generated.default.ScSpecType.scSpecTypeU128():
    case curr_generated.default.ScSpecType.scSpecTypeI128():
    case curr_generated.default.ScSpecType.scSpecTypeU256():
    case curr_generated.default.ScSpecType.scSpecTypeI256():
    case curr_generated.default.ScSpecType.scSpecTypeString():
    case curr_generated.default.ScSpecType.scSpecTypeSymbol():
      return;
  }
  const nestedTypes = extractNestedTypes(typeDef);
  nestedTypes.forEach((nested) => visitTypeDef(nested, accumulator));
}
function generateTypeImports(typeDefs) {
  const imports = {
    typeFileImports: /* @__PURE__ */ new Set(),
    stellarContractImports: /* @__PURE__ */ new Set(),
    stellarImports: /* @__PURE__ */ new Set(),
    needsBufferImport: false
  };
  typeDefs.forEach((typeDef) => visitTypeDef(typeDef, imports));
  return imports;
}
function formatImports(imports, options) {
  const importLines = [];
  const typeFileImports = imports.typeFileImports;
  const stellarContractImports = [
    ...imports.stellarContractImports,
    ...options?.additionalStellarContractImports || []
  ];
  const stellarImports = [
    ...imports.stellarImports,
    ...options?.additionalStellarImports || []
  ];
  if (options?.includeTypeFileImports && typeFileImports.size > 0) {
    importLines.push(
      `import {${Array.from(typeFileImports).join(", ")}} from './types.js';`
    );
  }
  if (stellarContractImports.length > 0) {
    const uniqueContractImports = Array.from(new Set(stellarContractImports));
    importLines.push(
      `import {${uniqueContractImports.join(", ")}} from '@stellar/stellar-sdk/contract';`
    );
  }
  if (stellarImports.length > 0) {
    const uniqueStellarImports = Array.from(new Set(stellarImports));
    importLines.push(
      `import {${uniqueStellarImports.join(", ")}} from '@stellar/stellar-sdk';`
    );
  }
  if (imports.needsBufferImport) {
    importLines.push(`import { Buffer } from 'buffer';`);
  }
  return importLines.join("\n");
}
function escapeJSDocContent(text) {
  return text.replace(/\*\//g, "* /").replace(
    /@(?!(param|returns?|type|throws?|example|deprecated|see|link|since|author|version|description|summary)\b)/g,
    "\\@"
  );
}
function formatJSDocComment(comment, indentLevel = 0) {
  if (comment.trim() === "") {
    return "";
  }
  const indent = " ".repeat(indentLevel);
  const escapedComment = escapeJSDocContent(comment);
  const lines = escapedComment.split("\n").map((line) => `${indent} * ${line}`.trimEnd());
  return `${indent}/**
${lines.join("\n")}
${indent} */
`;
}
function isTupleStruct(udtStruct) {
  const fields = udtStruct.fields();
  return fields.every(
    (field, index) => field.name().toString().trim() === index.toString()
  );
}

exports.escapeStringLiteral = escapeStringLiteral;
exports.formatImports = formatImports;
exports.formatJSDocComment = formatJSDocComment;
exports.generateTypeImports = generateTypeImports;
exports.isNameReserved = isNameReserved;
exports.isTupleStruct = isTupleStruct;
exports.parseTypeFromTypeDef = parseTypeFromTypeDef;
exports.sanitizeIdentifier = sanitizeIdentifier;
//# sourceMappingURL=utils.js.map

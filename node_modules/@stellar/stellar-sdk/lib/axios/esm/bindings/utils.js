import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import types from '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';

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
    case types.ScSpecType.scSpecTypeVal():
      return "any";
    case types.ScSpecType.scSpecTypeBool():
      return "boolean";
    case types.ScSpecType.scSpecTypeVoid():
      return "null";
    case types.ScSpecType.scSpecTypeError():
      return "Error";
    case types.ScSpecType.scSpecTypeU32():
    case types.ScSpecType.scSpecTypeI32():
      return "number";
    case types.ScSpecType.scSpecTypeU64():
    case types.ScSpecType.scSpecTypeI64():
    case types.ScSpecType.scSpecTypeTimepoint():
    case types.ScSpecType.scSpecTypeDuration():
    case types.ScSpecType.scSpecTypeU128():
    case types.ScSpecType.scSpecTypeI128():
    case types.ScSpecType.scSpecTypeU256():
    case types.ScSpecType.scSpecTypeI256():
      return "bigint";
    case types.ScSpecType.scSpecTypeBytes():
    case types.ScSpecType.scSpecTypeBytesN():
      return "Buffer";
    case types.ScSpecType.scSpecTypeString():
      return "string";
    case types.ScSpecType.scSpecTypeSymbol():
      return "string";
    case types.ScSpecType.scSpecTypeAddress():
    case types.ScSpecType.scSpecTypeMuxedAddress(): {
      if (isFunctionInput) {
        return "string | Address";
      }
      return "string";
    }
    case types.ScSpecType.scSpecTypeVec(): {
      const vecType = parseTypeFromTypeDef(
        typeDef.vec().elementType(),
        isFunctionInput
      );
      return `Array<${vecType}>`;
    }
    case types.ScSpecType.scSpecTypeMap(): {
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
    case types.ScSpecType.scSpecTypeTuple(): {
      const tupleTypes = typeDef.tuple().valueTypes().map(
        (t) => parseTypeFromTypeDef(t, isFunctionInput)
      );
      return `[${tupleTypes.join(", ")}]`;
    }
    case types.ScSpecType.scSpecTypeOption(): {
      while (typeDef.option().valueType().switch() === types.ScSpecType.scSpecTypeOption()) {
        typeDef = typeDef.option().valueType();
      }
      const optionType = parseTypeFromTypeDef(
        typeDef.option().valueType(),
        isFunctionInput
      );
      return `${optionType} | null`;
    }
    case types.ScSpecType.scSpecTypeResult(): {
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
    case types.ScSpecType.scSpecTypeUdt(): {
      const udtName = sanitizeIdentifier(typeDef.udt().name().toString());
      return udtName;
    }
    default:
      return "unknown";
  }
}
function extractNestedTypes(typeDef) {
  switch (typeDef.switch()) {
    case types.ScSpecType.scSpecTypeVec():
      return [typeDef.vec().elementType()];
    case types.ScSpecType.scSpecTypeMap():
      return [typeDef.map().keyType(), typeDef.map().valueType()];
    case types.ScSpecType.scSpecTypeTuple():
      return typeDef.tuple().valueTypes();
    case types.ScSpecType.scSpecTypeOption():
      return [typeDef.option().valueType()];
    case types.ScSpecType.scSpecTypeResult():
      return [typeDef.result().okType(), typeDef.result().errorType()];
    default:
      return [];
  }
}
function visitTypeDef(typeDef, accumulator) {
  const typeSwitch = typeDef.switch();
  switch (typeSwitch) {
    case types.ScSpecType.scSpecTypeUdt():
      accumulator.typeFileImports.add(
        sanitizeIdentifier(typeDef.udt().name().toString())
      );
      return;
    case types.ScSpecType.scSpecTypeAddress():
    case types.ScSpecType.scSpecTypeMuxedAddress():
      accumulator.stellarImports.add("Address");
      return;
    case types.ScSpecType.scSpecTypeBytes():
    case types.ScSpecType.scSpecTypeBytesN():
      accumulator.needsBufferImport = true;
      return;
    case types.ScSpecType.scSpecTypeVal():
      accumulator.stellarImports.add("xdr");
      return;
    case types.ScSpecType.scSpecTypeResult():
      accumulator.stellarContractImports.add("Result");
      break;
    // Primitive types that need no imports
    case types.ScSpecType.scSpecTypeBool():
    case types.ScSpecType.scSpecTypeVoid():
    case types.ScSpecType.scSpecTypeError():
    case types.ScSpecType.scSpecTypeU32():
    case types.ScSpecType.scSpecTypeI32():
    case types.ScSpecType.scSpecTypeU64():
    case types.ScSpecType.scSpecTypeI64():
    case types.ScSpecType.scSpecTypeTimepoint():
    case types.ScSpecType.scSpecTypeDuration():
    case types.ScSpecType.scSpecTypeU128():
    case types.ScSpecType.scSpecTypeI128():
    case types.ScSpecType.scSpecTypeU256():
    case types.ScSpecType.scSpecTypeI256():
    case types.ScSpecType.scSpecTypeString():
    case types.ScSpecType.scSpecTypeSymbol():
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

export { escapeStringLiteral, formatImports, formatJSDocComment, generateTypeImports, isNameReserved, isTupleStruct, parseTypeFromTypeDef, sanitizeIdentifier };
//# sourceMappingURL=utils.js.map

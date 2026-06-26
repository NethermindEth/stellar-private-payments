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
var utils = require('./utils.js');

class TypeGenerator {
  spec;
  constructor(spec) {
    this.spec = spec;
  }
  /**
   * Generate all TypeScript type definitions
   */
  generate() {
    const types = this.spec.entries.map((entry) => this.generateEntry(entry)).filter((t) => t).join("\n\n");
    const imports = this.generateImports();
    return `${imports}

    ${types}
    `;
  }
  /**
   * Generate TypeScript for a single spec entry
   */
  generateEntry(entry) {
    switch (entry.switch()) {
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtStructV0():
        if (utils.isTupleStruct(entry.udtStructV0())) {
          return this.generateTupleStruct(entry.udtStructV0());
        }
        return this.generateStruct(entry.udtStructV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtUnionV0():
        return this.generateUnion(entry.udtUnionV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        return this.generateEnum(entry.udtEnumV0());
      case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0():
        return this.generateErrorEnum(entry.udtErrorEnumV0());
      default:
        return null;
    }
  }
  generateImports() {
    const imports = utils.generateTypeImports(
      this.spec.entries.flatMap((entry) => {
        switch (entry.switch()) {
          case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtStructV0():
            return entry.udtStructV0().fields().map((field) => field.type());
          case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtUnionV0():
            return entry.udtUnionV0().cases().flatMap((unionCase) => {
              if (unionCase.switch() === curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0()) {
                return unionCase.tupleCase().type();
              }
              return [];
            });
          case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtEnumV0():
            return [];
          case curr_generated.default.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0():
            return [];
          default:
            return [];
        }
      })
    );
    return utils.formatImports(imports, {
      includeTypeFileImports: false
      // Types file doesn't import from itself
    });
  }
  /**
   * Generate TypeScript interface for a struct
   */
  generateStruct(struct) {
    const name = utils.sanitizeIdentifier(struct.name().toString());
    const doc = utils.formatJSDocComment(
      struct.doc().toString() || `Struct: ${name}`,
      0
    );
    const fields = struct.fields().map((field) => {
      const fieldName = utils.sanitizeIdentifier(field.name().toString());
      const fieldType = utils.parseTypeFromTypeDef(field.type());
      const fieldDoc = utils.formatJSDocComment(field.doc().toString(), 2);
      return `${fieldDoc}  ${fieldName}: ${fieldType};`;
    }).join("\n");
    return `${doc}export interface ${name} {
${fields}
}`;
  }
  /**
   * Generate TypeScript union type
   */
  generateUnion(union) {
    const name = utils.sanitizeIdentifier(union.name().toString());
    const doc = utils.formatJSDocComment(
      union.doc().toString() || `Union: ${name}`,
      0
    );
    const cases = union.cases().map((unionCase) => this.generateUnionCase(unionCase));
    const caseTypes = cases.map((c) => {
      if (c.types.length > 0) {
        return `${utils.formatJSDocComment(c.doc, 2)}  { tag: "${utils.escapeStringLiteral(c.name)}"; values: readonly [${c.types.join(", ")}] }`;
      }
      return `${utils.formatJSDocComment(c.doc, 2)}  { tag: "${utils.escapeStringLiteral(c.name)}"; values: void }`;
    }).join(" |\n");
    return `${doc} export type ${name} =
${caseTypes};`;
  }
  /**
   * Generate TypeScript enum
   */
  generateEnum(enumEntry) {
    const name = utils.sanitizeIdentifier(enumEntry.name().toString());
    const doc = utils.formatJSDocComment(
      enumEntry.doc().toString() || `Enum: ${name}`,
      0
    );
    const members = enumEntry.cases().map((enumCase) => {
      const caseName = utils.sanitizeIdentifier(enumCase.name().toString());
      const caseValue = enumCase.value();
      const caseDoc = enumCase.doc().toString() || `Enum Case: ${caseName}`;
      return `${utils.formatJSDocComment(caseDoc, 2)}  ${caseName} = ${caseValue}`;
    }).join(",\n");
    return `${doc}export enum ${name} {
${members}
}`;
  }
  /**
   * Generate TypeScript error enum
   */
  generateErrorEnum(errorEnum) {
    const name = utils.sanitizeIdentifier(errorEnum.name().toString());
    const doc = utils.formatJSDocComment(
      errorEnum.doc().toString() || `Error Enum: ${name}`,
      0
    );
    const cases = errorEnum.cases().map((enumCase) => this.generateEnumCase(enumCase));
    const members = cases.map((c) => {
      return `${utils.formatJSDocComment(c.doc, 2)}  ${c.value} : { message: "${utils.escapeStringLiteral(c.name)}" }`;
    }).join(",\n");
    return `${doc}export const ${name} = {
${members}
}`;
  }
  /**
   * Generate union case
   */
  generateUnionCase(unionCase) {
    switch (unionCase.switch()) {
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0(): {
        const voidCase = unionCase.voidCase();
        return {
          doc: voidCase.doc().toString(),
          name: voidCase.name().toString(),
          types: []
        };
      }
      case curr_generated.default.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0(): {
        const tupleCase = unionCase.tupleCase();
        return {
          doc: tupleCase.doc().toString(),
          name: tupleCase.name().toString(),
          types: tupleCase.type().map((t) => utils.parseTypeFromTypeDef(t))
        };
      }
      default:
        throw new Error(`Unknown union case kind: ${unionCase.switch()}`);
    }
  }
  /**
   * Generate enum case
   */
  generateEnumCase(enumCase) {
    return {
      doc: enumCase.doc().toString(),
      name: enumCase.name().toString(),
      value: enumCase.value()
    };
  }
  generateTupleStruct(udtStruct) {
    const name = utils.sanitizeIdentifier(udtStruct.name().toString());
    const doc = utils.formatJSDocComment(
      udtStruct.doc().toString() || `Tuple Struct: ${name}`,
      0
    );
    const types = udtStruct.fields().map((field) => utils.parseTypeFromTypeDef(field.type())).join(", ");
    return `${doc}export type ${name} = readonly [${types}];`;
  }
}

exports.TypeGenerator = TypeGenerator;
//# sourceMappingURL=types.js.map

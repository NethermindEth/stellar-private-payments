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
import { isTupleStruct, generateTypeImports, formatImports, sanitizeIdentifier, formatJSDocComment, parseTypeFromTypeDef, escapeStringLiteral } from './utils.js';

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
      case types.ScSpecEntryKind.scSpecEntryUdtStructV0():
        if (isTupleStruct(entry.udtStructV0())) {
          return this.generateTupleStruct(entry.udtStructV0());
        }
        return this.generateStruct(entry.udtStructV0());
      case types.ScSpecEntryKind.scSpecEntryUdtUnionV0():
        return this.generateUnion(entry.udtUnionV0());
      case types.ScSpecEntryKind.scSpecEntryUdtEnumV0():
        return this.generateEnum(entry.udtEnumV0());
      case types.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0():
        return this.generateErrorEnum(entry.udtErrorEnumV0());
      default:
        return null;
    }
  }
  generateImports() {
    const imports = generateTypeImports(
      this.spec.entries.flatMap((entry) => {
        switch (entry.switch()) {
          case types.ScSpecEntryKind.scSpecEntryUdtStructV0():
            return entry.udtStructV0().fields().map((field) => field.type());
          case types.ScSpecEntryKind.scSpecEntryUdtUnionV0():
            return entry.udtUnionV0().cases().flatMap((unionCase) => {
              if (unionCase.switch() === types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0()) {
                return unionCase.tupleCase().type();
              }
              return [];
            });
          case types.ScSpecEntryKind.scSpecEntryUdtEnumV0():
            return [];
          case types.ScSpecEntryKind.scSpecEntryUdtErrorEnumV0():
            return [];
          default:
            return [];
        }
      })
    );
    return formatImports(imports, {
      includeTypeFileImports: false
      // Types file doesn't import from itself
    });
  }
  /**
   * Generate TypeScript interface for a struct
   */
  generateStruct(struct) {
    const name = sanitizeIdentifier(struct.name().toString());
    const doc = formatJSDocComment(
      struct.doc().toString() || `Struct: ${name}`,
      0
    );
    const fields = struct.fields().map((field) => {
      const fieldName = sanitizeIdentifier(field.name().toString());
      const fieldType = parseTypeFromTypeDef(field.type());
      const fieldDoc = formatJSDocComment(field.doc().toString(), 2);
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
    const name = sanitizeIdentifier(union.name().toString());
    const doc = formatJSDocComment(
      union.doc().toString() || `Union: ${name}`,
      0
    );
    const cases = union.cases().map((unionCase) => this.generateUnionCase(unionCase));
    const caseTypes = cases.map((c) => {
      if (c.types.length > 0) {
        return `${formatJSDocComment(c.doc, 2)}  { tag: "${escapeStringLiteral(c.name)}"; values: readonly [${c.types.join(", ")}] }`;
      }
      return `${formatJSDocComment(c.doc, 2)}  { tag: "${escapeStringLiteral(c.name)}"; values: void }`;
    }).join(" |\n");
    return `${doc} export type ${name} =
${caseTypes};`;
  }
  /**
   * Generate TypeScript enum
   */
  generateEnum(enumEntry) {
    const name = sanitizeIdentifier(enumEntry.name().toString());
    const doc = formatJSDocComment(
      enumEntry.doc().toString() || `Enum: ${name}`,
      0
    );
    const members = enumEntry.cases().map((enumCase) => {
      const caseName = sanitizeIdentifier(enumCase.name().toString());
      const caseValue = enumCase.value();
      const caseDoc = enumCase.doc().toString() || `Enum Case: ${caseName}`;
      return `${formatJSDocComment(caseDoc, 2)}  ${caseName} = ${caseValue}`;
    }).join(",\n");
    return `${doc}export enum ${name} {
${members}
}`;
  }
  /**
   * Generate TypeScript error enum
   */
  generateErrorEnum(errorEnum) {
    const name = sanitizeIdentifier(errorEnum.name().toString());
    const doc = formatJSDocComment(
      errorEnum.doc().toString() || `Error Enum: ${name}`,
      0
    );
    const cases = errorEnum.cases().map((enumCase) => this.generateEnumCase(enumCase));
    const members = cases.map((c) => {
      return `${formatJSDocComment(c.doc, 2)}  ${c.value} : { message: "${escapeStringLiteral(c.name)}" }`;
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
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseVoidV0(): {
        const voidCase = unionCase.voidCase();
        return {
          doc: voidCase.doc().toString(),
          name: voidCase.name().toString(),
          types: []
        };
      }
      case types.ScSpecUdtUnionCaseV0Kind.scSpecUdtUnionCaseTupleV0(): {
        const tupleCase = unionCase.tupleCase();
        return {
          doc: tupleCase.doc().toString(),
          name: tupleCase.name().toString(),
          types: tupleCase.type().map((t) => parseTypeFromTypeDef(t))
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
    const name = sanitizeIdentifier(udtStruct.name().toString());
    const doc = formatJSDocComment(
      udtStruct.doc().toString() || `Tuple Struct: ${name}`,
      0
    );
    const types = udtStruct.fields().map((field) => parseTypeFromTypeDef(field.type())).join(", ");
    return `${doc}export type ${name} = readonly [${types}];`;
  }
}

export { TypeGenerator };
//# sourceMappingURL=types.js.map

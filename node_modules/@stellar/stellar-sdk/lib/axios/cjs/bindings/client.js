'use strict';

var utils = require('./utils.js');

class ClientGenerator {
  spec;
  constructor(spec) {
    this.spec = spec;
  }
  /**
   * Generate client class
   */
  generate() {
    let deployMethod = "";
    try {
      const constructorFunc = this.spec.getFunc("__constructor");
      deployMethod = this.generateDeployMethod(constructorFunc);
    } catch {
      deployMethod = this.generateDeployMethod(void 0);
    }
    const interfaceMethods = this.spec.funcs().filter((func) => func.name().toString() !== "__constructor").map((func) => this.generateInterfaceMethod(func)).join("\n");
    const imports = this.generateImports();
    const specEntries = this.spec.entries.map(
      (entry) => `"${entry.toXDR("base64")}"`
    );
    const fromJSON = this.spec.funcs().filter((func) => func.name().toString() !== "__constructor").map((func) => this.generateFromJSONMethod(func)).join(",");
    return `${imports}

export interface Client {
${interfaceMethods}
}

export class Client extends ContractClient {
  constructor(public readonly options: ContractClientOptions) {
    super(
      new Spec([${specEntries.join(", ")}]),
      options
    );
  }

 ${deployMethod}
  public readonly fromJSON = {
  ${fromJSON}
  };
}`;
  }
  generateImports() {
    const imports = utils.generateTypeImports(
      this.spec.funcs().flatMap((func) => {
        const inputs = func.inputs();
        const outputs = func.outputs();
        const defs = inputs.map((input) => input.type()).concat(outputs);
        return defs;
      })
    );
    return utils.formatImports(imports, {
      includeTypeFileImports: true,
      // Client imports types
      additionalStellarContractImports: [
        "Spec",
        "AssembledTransaction",
        "Client as ContractClient",
        "ClientOptions as ContractClientOptions",
        "MethodOptions"
      ]
    });
  }
  /**
   * Generate interface method signature
   */
  generateInterfaceMethod(func) {
    const name = utils.sanitizeIdentifier(func.name().toString());
    const inputs = func.inputs().map((input) => ({
      name: utils.sanitizeIdentifier(input.name().toString()),
      type: utils.parseTypeFromTypeDef(input.type(), true)
    }));
    const outputType = func.outputs().length > 0 ? utils.parseTypeFromTypeDef(func.outputs()[0]) : "void";
    const docs = utils.formatJSDocComment(func.doc().toString(), 2);
    const params = this.formatMethodParameters(inputs);
    return `${docs}  ${name}(${params}): Promise<AssembledTransaction<${outputType}>>;`;
  }
  generateFromJSONMethod(func) {
    const name = utils.sanitizeIdentifier(func.name().toString());
    const outputType = func.outputs().length > 0 ? utils.parseTypeFromTypeDef(func.outputs()[0]) : "void";
    return `  ${name} : this.txFromJSON<${outputType}>`;
  }
  /**
   * Generate deploy method
   */
  generateDeployMethod(constructorFunc) {
    if (!constructorFunc) {
      const params2 = this.formatConstructorParameters([]);
      return `  static deploy<T = Client>(${params2}): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options);
  }`;
    }
    const inputs = constructorFunc.inputs().map((input) => ({
      name: utils.sanitizeIdentifier(input.name().toString()),
      type: utils.parseTypeFromTypeDef(input.type(), true)
    }));
    const params = this.formatConstructorParameters(inputs);
    const inputsDestructure = inputs.length > 0 ? `{ ${inputs.map((i) => i.name).join(", ")} }, ` : "";
    return `  static deploy<T = Client>(${params}): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(${inputsDestructure}options);
  }`;
  }
  /**
   * Format method parameters
   */
  formatMethodParameters(inputs) {
    const params = [];
    if (inputs.length > 0) {
      const inputsParam = `{ ${inputs.map((i) => `${i.name}: ${i.type}`).join("; ")} }`;
      params.push(
        `{ ${inputs.map((i) => i.name).join(", ")} }: ${inputsParam}`
      );
    }
    params.push("options?: MethodOptions");
    return params.join(", ");
  }
  /**
   * Format constructor parameters
   */
  formatConstructorParameters(inputs) {
    const params = [];
    if (inputs.length > 0) {
      const inputsParam = `{ ${inputs.map((i) => `${i.name}: ${i.type}`).join("; ")} }`;
      params.push(
        `{ ${inputs.map((i) => i.name).join(", ")} }: ${inputsParam}`
      );
    }
    params.push(
      `options: MethodOptions & Omit<ContractClientOptions, 'contractId'> & { wasmHash: Buffer | string; salt?: Buffer | Uint8Array; format?: "hex" | "base64"; address?: string; }`
    );
    return params.join(", ");
  }
}

exports.ClientGenerator = ClientGenerator;
//# sourceMappingURL=client.js.map

import { Spec } from "../contract/index.js";
/**
 * Generates TypeScript client class for contract methods
 */
export declare class ClientGenerator {
    private spec;
    constructor(spec: Spec);
    /**
     * Generate client class
     */
    generate(): string;
    private generateImports;
    /**
     * Generate interface method signature
     */
    private generateInterfaceMethod;
    private generateFromJSONMethod;
    /**
     * Generate deploy method
     */
    private generateDeployMethod;
    /**
     * Format method parameters
     */
    private formatMethodParameters;
    /**
     * Format constructor parameters
     */
    private formatConstructorParameters;
}

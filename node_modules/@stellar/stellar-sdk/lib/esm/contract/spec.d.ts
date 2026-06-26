import type { JSONSchema7 } from "json-schema";
import { xdr } from "../base/index.js";
export interface Union<T> {
    tag: string;
    values?: T;
}
/**
 * Provides a ContractSpec class which can contains the XDR types defined by the contract.
 * This allows the class to be used to convert between native and raw `xdr.ScVal`s.
 *
 * Constructs a new ContractSpec from an array of XDR spec entries.
 *
 * @param entries - the XDR spec entries
 * @throws if entries is invalid
 *
 * @example
 * ```ts
 * const specEntries = [...]; // XDR spec entries of a smart contract
 * const contractSpec = new ContractSpec(specEntries);
 *
 * // Convert native value to ScVal
 * const args = {
 *   arg1: 'value1',
 *   arg2: 1234
 * };
 * const scArgs = contractSpec.funcArgsToScVals('funcName', args);
 *
 * // Call contract
 * const resultScv = await callContract(contractId, 'funcName', scArgs);
 *
 * // Convert result ScVal back to native value
 * const result = contractSpec.funcResToNative('funcName', resultScv);
 *
 * console.log(result); // {success: true}
 * ```
 */
export declare class Spec {
    /**
     * The XDR spec entries.
     */
    entries: xdr.ScSpecEntry[];
    /**
     * Generates a Spec instance from the contract's wasm binary.
     *
     * @param wasm - The contract's wasm binary as a Buffer.
     * @returns A Promise that resolves to a Spec instance.
     * @throws If the contract spec cannot be obtained from the provided wasm binary.
     */
    static fromWasm(wasm: Buffer): Spec;
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
    constructor(entries: Buffer | string | xdr.ScSpecEntry[] | string[]);
    /**
     * Gets the XDR functions from the spec.
     * @returns all contract functions
     */
    funcs(): xdr.ScSpecFunctionV0[];
    /**
     * Gets the XDR function spec for the given function name.
     *
     * @param name - the name of the function
     * @returns the function spec
     *
     * @throws if no function with the given name exists
     */
    getFunc(name: string): xdr.ScSpecFunctionV0;
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
    funcArgsToScVals(name: string, args: object): xdr.ScVal[];
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
    funcResToNative(name: string, val_or_base64: xdr.ScVal | string): any;
    /**
     * Finds the XDR spec entry for the given name.
     *
     * @param name - the name to find
     * @returns the entry
     *
     * @throws if no entry with the given name exists
     */
    findEntry(name: string): xdr.ScSpecEntry;
    /**
     * Converts a native JS value to an ScVal based on the given type.
     *
     * @param val - the native JS value
     * @param ty - (optional) the expected type
     * @returns the converted ScVal
     *
     * @throws if value cannot be converted to the given type
     */
    nativeToScVal(val: any, ty: xdr.ScSpecTypeDef): xdr.ScVal;
    private nativeToUdt;
    private nativeToUnion;
    private nativeToStruct;
    private nativeToEnum;
    /**
     * Converts an base64 encoded ScVal back to a native JS value based on the given type.
     *
     * @param scv - the base64 encoded ScVal
     * @param typeDef - the expected type
     * @returns the converted native JS value
     *
     * @throws if ScVal cannot be converted to the given type
     */
    scValStrToNative<T>(scv: string, typeDef: xdr.ScSpecTypeDef): T;
    /**
     * Converts an ScVal back to a native JS value based on the given type.
     *
     * @param scv - the ScVal
     * @param typeDef - the expected type
     * @returns the converted native JS value
     *
     * @throws if ScVal cannot be converted to the given type
     */
    scValToNative<T>(scv: xdr.ScVal, typeDef: xdr.ScSpecTypeDef): T;
    private scValUdtToNative;
    private unionToNative;
    private structToNative;
    private enumToNative;
    /**
     * Gets the XDR error cases from the spec.
     *
     * @returns all contract functions
     *
     */
    errorCases(): xdr.ScSpecUdtErrorEnumCaseV0[];
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
    jsonSchema(funcName?: string): JSONSchema7;
}

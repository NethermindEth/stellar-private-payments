import { Spec } from "./spec.js";
import { AssembledTransaction } from "./assembled_transaction.js";
import type { ClientOptions, MethodOptions } from "./types.js";
/**
 * Generate a class from the contract spec that where each contract method
 * gets included with an identical name.
 *
 * Each method returns an {@link contract.AssembledTransaction | AssembledTransaction} that can
 * be used to modify, simulate, decode results, and possibly sign, & submit the
 * transaction.
 *
 *
 * @param spec - {@link Spec} to construct a Client for
 * @param options - see {@link ClientOptions}
 */
export declare class Client {
    readonly spec: Spec;
    readonly options: ClientOptions;
    static deploy<T = Client>(
    /** Constructor/Initialization Args for the contract's `__constructor` method */
    args: Record<string, any> | null, 
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions & Omit<ClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
        /** The address to use to deploy the custom contract */
        address?: string;
    }): Promise<AssembledTransaction<T>>;
    constructor(spec: Spec, options: ClientOptions);
    /**
     * Generates a Client instance from the provided ClientOptions and the contract's wasm hash.
     * The wasmHash can be provided in either hex or base64 format.
     *
     * @param wasmHash - The hash of the contract's wasm binary, in either hex or base64 format.
     * @param options - The ClientOptions object containing the necessary configuration, including the rpcUrl.
     * @param format - (optional) The format of the provided wasmHash, either "hex" or "base64". Defaults to "hex".
     * @returns A Promise that resolves to a Client instance.
     * @throws If the provided options object does not contain an rpcUrl.
     */
    static fromWasmHash(wasmHash: Buffer | string, options: ClientOptions, format?: "hex" | "base64"): Promise<Client>;
    /**
     * Generates a Client instance from the provided ClientOptions and the contract's wasm binary.
     *
     * @param wasm - The contract's wasm binary as a Buffer.
     * @param options - The ClientOptions object containing the necessary configuration.
     * @returns A Promise that resolves to a Client instance.
     * @throws If the contract spec cannot be obtained from the provided wasm binary.
     */
    static fromWasm(wasm: Buffer, options: ClientOptions): Promise<Client>;
    /**
     * Generates a Client instance from the provided ClientOptions, which must include the contractId and rpcUrl.
     *
     * @param options - The ClientOptions object containing the necessary configuration, including the contractId and rpcUrl.
     * @returns A Promise that resolves to a Client instance.
     * @throws If the provided options object does not contain both rpcUrl and contractId.
     */
    static from(options: ClientOptions): Promise<Client>;
    txFromJSON: <T>(json: string) => AssembledTransaction<T>;
    txFromXDR: <T>(xdrBase64: string) => AssembledTransaction<T>;
}

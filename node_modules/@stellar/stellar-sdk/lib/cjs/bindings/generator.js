'use strict';

require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('../base/generated/curr_generated.js');
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
require('../rpc/api.js');
var spec = require('../contract/spec.js');
var config = require('./config.js');
var types = require('./types.js');
var client = require('./client.js');
var wasm_spec_parser = require('../contract/wasm_spec_parser.js');
var wasm_fetcher = require('./wasm_fetcher.js');
var sacSpec = require('./sac-spec.js');

class BindingGenerator {
  spec;
  /**
   * Private constructor - use static factory methods instead.
   *
   * @param spec - The parsed contract specification
   */
  constructor(spec) {
    this.spec = spec;
  }
  /**
   * Creates a BindingGenerator from an existing Spec object.
   *
   * Use this when you already have a parsed contract specification,
   * such as from manually constructed spec entries or from another source.
   *
   * @param spec - The contract specification containing function and type definitions
   * @returns A new BindingGenerator instance
   *
   * @example
   * ```ts
   * const spec = new Spec(specEntries);
   * const generator = BindingGenerator.fromSpec(spec);
   * ```
   */
  static fromSpec(spec) {
    return new BindingGenerator(spec);
  }
  /**
   * Creates a BindingGenerator from a WASM binary buffer.
   *
   * Parses the contract specification directly from the WASM file's custom section.
   * This is the most common method when working with locally compiled contracts.
   *
   * @param wasmBuffer - The raw WASM binary as a Buffer
   * @returns A Promise resolving to a new BindingGenerator instance
   * @throws If the WASM file doesn't contain a valid contract spec
   *
   * @example
   * ```ts
   * const wasmBuffer = fs.readFileSync("./target/wasm32-unknown-unknown/release/my_contract.wasm");
   * const generator = await BindingGenerator.fromWasm(wasmBuffer);
   * ```
   */
  static fromWasm(wasmBuffer) {
    const spec$1 = new spec.Spec(wasm_spec_parser.specFromWasm(wasmBuffer));
    return new BindingGenerator(spec$1);
  }
  /**
   * Creates a BindingGenerator by fetching WASM from the network using its hash.
   *
   * Retrieves the WASM bytecode from Stellar RPC using the WASM hash,
   * then parses the contract specification from it. Useful when you know
   * the hash of an installed WASM but don't have the binary locally.
   *
   * @param wasmHash - The hex-encoded hash of the installed WASM blob
   * @param rpcServer - The Stellar RPC server instance
   * @returns A Promise resolving to a new BindingGenerator instance
   * @throws If the WASM cannot be fetched or doesn't contain a valid spec
   *
   * @example
   * ```ts
   * const generator = await BindingGenerator.fromWasmHash(
   *   "a1b2c3...xyz",
   *   "https://soroban-testnet.stellar.org",
   *   Networks.TESTNET
   * );
   * ```
   */
  static async fromWasmHash(wasmHash, rpcServer) {
    const wasm = await wasm_fetcher.fetchFromWasmHash(wasmHash, rpcServer);
    if (wasm.type !== "wasm") {
      throw new Error("Fetched contract is not of type 'wasm'");
    }
    return BindingGenerator.fromWasm(wasm.wasmBytes);
  }
  /**
   * Creates a BindingGenerator by fetching contract info from a deployed contract ID.
   *
   * Retrieves the contract's WASM from the network using the contract ID,
   * then parses the specification. If the contract is a Stellar Asset Contract (SAC),
   * returns a generator with the standard SAC specification.
   *
   * @param contractId - The contract ID (C... address) of the deployed contract
   * @param rpcServer - The Stellar RPC server instance
   * @returns A Promise resolving to a new BindingGenerator instance
   * @throws If the contract cannot be found or fetched
   *
   * @example
   * ```ts
   * const generator = await BindingGenerator.fromContractId(
   *   "CABC123...XYZ",
   *   rpcServer
   * );
   * ```
   */
  static async fromContractId(contractId, rpcServer) {
    const result = await wasm_fetcher.fetchFromContractId(contractId, rpcServer);
    if (result.type === "wasm") {
      return BindingGenerator.fromWasm(result.wasmBytes);
    }
    const spec$1 = new spec.Spec(sacSpec.SAC_SPEC);
    return BindingGenerator.fromSpec(spec$1);
  }
  /**
   * Generates TypeScript bindings for the contract.
   *
   * Produces all the files needed for a standalone npm package:
   * - `client.ts`: A typed Client class with methods for each contract function
   * - `types.ts`: TypeScript interfaces for all contract types (structs, enums, unions)
   * - `index.ts`: Barrel export file
   * - `package.json`, `tsconfig.json`, `README.md`, `.gitignore`: Package configuration
   *
   * The generated code does not write to disk - use the returned strings
   * to write files as needed.
   *
   * @param options - Configuration options for generation
   *   - `contractName`: Required. The name for the generated package (kebab-case recommended)
   * @returns An object containing all generated file contents as strings
   * @throws If contractName is missing or empty
   *
   * @example
   * ```ts
   * const bindings = generator.generate({
   *   contractName: "my-token",
   *   contractAddress: "CABC...XYZ",
   *   rpcUrl: "https://soroban-testnet.stellar.org",
   *   networkPassphrase: Networks.TESTNET
   * });
   *
   * // Write files to disk
   * fs.writeFileSync("./src/client.ts", bindings.client);
   * fs.writeFileSync("./src/types.ts", bindings.types);
   * ```
   */
  generate(options) {
    this.validateOptions(options);
    const typeGenerator = new types.TypeGenerator(this.spec);
    const clientGenerator = new client.ClientGenerator(this.spec);
    const types$1 = typeGenerator.generate();
    const client$1 = clientGenerator.generate();
    let index = `export { Client } from "./client.js";`;
    if (types$1.trim() !== "") {
      index = index.concat(`
export * from "./types.js";`);
    }
    const configGenerator = new config.ConfigGenerator();
    const { packageJson, tsConfig, readme, gitignore } = configGenerator.generate(options);
    return {
      index,
      types: types$1,
      client: client$1,
      packageJson,
      tsConfig,
      readme,
      gitignore
    };
  }
  /**
   * Validates that required generation options are provided.
   *
   * @param options - The options to validate
   * @throws If contractName is missing or empty
   */
  validateOptions(options) {
    if (!options.contractName || options.contractName.trim() === "") {
      throw new Error("contractName is required and cannot be empty");
    }
  }
}

exports.BindingGenerator = BindingGenerator;
//# sourceMappingURL=generator.js.map

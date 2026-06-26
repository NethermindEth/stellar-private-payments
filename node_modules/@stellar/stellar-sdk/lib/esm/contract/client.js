import { Buffer } from 'buffer';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import { Operation } from '../base/operation.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import { Address } from '../base/address.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { Spec } from './spec.js';
import '../rpc/api.js';
import { RpcServer } from '../rpc/server.js';
import { AssembledTransaction } from './assembled_transaction.js';
import { sanitizeIdentifier } from '../bindings/utils.js';

const CONSTRUCTOR_FUNC = "__constructor";
async function specFromWasmHash(wasmHash, options, format = "hex") {
  if (!options || !options.rpcUrl) {
    throw new TypeError("options must contain rpcUrl");
  }
  const { rpcUrl, allowHttp, headers } = options;
  const serverOpts = { allowHttp, headers };
  const server = new RpcServer(rpcUrl, serverOpts);
  const wasm = await server.getContractWasmByHash(wasmHash, format);
  return Spec.fromWasm(wasm);
}
class Client {
  constructor(spec, options) {
    this.spec = spec;
    this.options = options;
    if (options.server === void 0) {
      const { allowHttp, headers } = options;
      options.server = new RpcServer(options.rpcUrl, {
        allowHttp,
        headers
      });
    }
    this.spec.funcs().forEach((xdrFn) => {
      const method = xdrFn.name().toString();
      if (method === CONSTRUCTOR_FUNC) {
        return;
      }
      const assembleTransaction = (args, methodOptions) => AssembledTransaction.build({
        method,
        args: args && spec.funcArgsToScVals(method, args),
        ...options,
        ...methodOptions,
        errorTypes: spec.errorCases().reduce(
          (acc, curr) => ({
            ...acc,
            [curr.value()]: { message: curr.doc().toString() }
          }),
          {}
        ),
        parseResultXdr: (result) => spec.funcResToNative(method, result)
      });
      this[sanitizeIdentifier(method)] = spec.getFunc(method).inputs().length === 0 ? (opts) => assembleTransaction(void 0, opts) : assembleTransaction;
    });
  }
  spec;
  options;
  static async deploy(args, options) {
    const {
      wasmHash,
      salt,
      format,
      fee,
      timeoutInSeconds,
      simulate,
      ...clientOptions
    } = options;
    const spec = await specFromWasmHash(wasmHash, clientOptions, format);
    const operation = Operation.createCustomContract({
      address: new Address(options.address || options.publicKey),
      wasmHash: typeof wasmHash === "string" ? Buffer.from(wasmHash, format ?? "hex") : wasmHash,
      salt,
      constructorArgs: args ? spec.funcArgsToScVals(CONSTRUCTOR_FUNC, args) : []
    });
    return AssembledTransaction.buildWithOp(operation, {
      fee,
      timeoutInSeconds,
      simulate,
      ...clientOptions,
      contractId: "ignored",
      method: CONSTRUCTOR_FUNC,
      parseResultXdr: (result) => new Client(spec, {
        ...clientOptions,
        contractId: Address.fromScVal(result).toString()
      })
    });
  }
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
  static async fromWasmHash(wasmHash, options, format = "hex") {
    if (!options || !options.rpcUrl) {
      throw new TypeError("options must contain rpcUrl");
    }
    const { rpcUrl, allowHttp, headers } = options;
    const server = options.server ?? new RpcServer(rpcUrl, {
      allowHttp,
      headers
    });
    const wasm = await server.getContractWasmByHash(wasmHash, format);
    return Client.fromWasm(wasm, options);
  }
  /**
   * Generates a Client instance from the provided ClientOptions and the contract's wasm binary.
   *
   * @param wasm - The contract's wasm binary as a Buffer.
   * @param options - The ClientOptions object containing the necessary configuration.
   * @returns A Promise that resolves to a Client instance.
   * @throws If the contract spec cannot be obtained from the provided wasm binary.
   */
  static async fromWasm(wasm, options) {
    const spec = await Spec.fromWasm(wasm);
    return new Client(spec, options);
  }
  /**
   * Generates a Client instance from the provided ClientOptions, which must include the contractId and rpcUrl.
   *
   * @param options - The ClientOptions object containing the necessary configuration, including the contractId and rpcUrl.
   * @returns A Promise that resolves to a Client instance.
   * @throws If the provided options object does not contain both rpcUrl and contractId.
   */
  static async from(options) {
    if (!options || !options.rpcUrl || !options.contractId) {
      throw new TypeError("options must contain rpcUrl and contractId");
    }
    const { rpcUrl, contractId, allowHttp, headers } = options;
    const server = new RpcServer(rpcUrl, {
      allowHttp,
      headers
    });
    const wasm = await server.getContractWasmByContractId(contractId);
    return Client.fromWasm(wasm, options);
  }
  txFromJSON = (json) => {
    const { method, ...tx } = JSON.parse(json);
    return AssembledTransaction.fromJSON(
      {
        ...this.options,
        method,
        parseResultXdr: (result) => this.spec.funcResToNative(method, result)
      },
      tx
    );
  };
  txFromXDR = (xdrBase64) => AssembledTransaction.fromXDR(this.options, xdrBase64, this.spec);
}

export { Client };
//# sourceMappingURL=client.js.map

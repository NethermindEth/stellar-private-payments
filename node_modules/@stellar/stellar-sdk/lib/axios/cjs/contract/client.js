'use strict';

var buffer = require('buffer');
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
var operation = require('../base/operation.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var address = require('../base/address.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var spec = require('./spec.js');
require('../rpc/api.js');
var server = require('../rpc/server.js');
var assembled_transaction = require('./assembled_transaction.js');
var utils = require('../bindings/utils.js');

const CONSTRUCTOR_FUNC = "__constructor";
async function specFromWasmHash(wasmHash, options, format = "hex") {
  if (!options || !options.rpcUrl) {
    throw new TypeError("options must contain rpcUrl");
  }
  const { rpcUrl, allowHttp, headers } = options;
  const serverOpts = { allowHttp, headers };
  const server$1 = new server.RpcServer(rpcUrl, serverOpts);
  const wasm = await server$1.getContractWasmByHash(wasmHash, format);
  return spec.Spec.fromWasm(wasm);
}
class Client {
  constructor(spec, options) {
    this.spec = spec;
    this.options = options;
    if (options.server === void 0) {
      const { allowHttp, headers } = options;
      options.server = new server.RpcServer(options.rpcUrl, {
        allowHttp,
        headers
      });
    }
    this.spec.funcs().forEach((xdrFn) => {
      const method = xdrFn.name().toString();
      if (method === CONSTRUCTOR_FUNC) {
        return;
      }
      const assembleTransaction = (args, methodOptions) => assembled_transaction.AssembledTransaction.build({
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
      this[utils.sanitizeIdentifier(method)] = spec.getFunc(method).inputs().length === 0 ? (opts) => assembleTransaction(void 0, opts) : assembleTransaction;
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
    const operation$1 = operation.Operation.createCustomContract({
      address: new address.Address(options.address || options.publicKey),
      wasmHash: typeof wasmHash === "string" ? buffer.Buffer.from(wasmHash, format ?? "hex") : wasmHash,
      salt,
      constructorArgs: args ? spec.funcArgsToScVals(CONSTRUCTOR_FUNC, args) : []
    });
    return assembled_transaction.AssembledTransaction.buildWithOp(operation$1, {
      fee,
      timeoutInSeconds,
      simulate,
      ...clientOptions,
      contractId: "ignored",
      method: CONSTRUCTOR_FUNC,
      parseResultXdr: (result) => new Client(spec, {
        ...clientOptions,
        contractId: address.Address.fromScVal(result).toString()
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
    const server$1 = options.server ?? new server.RpcServer(rpcUrl, {
      allowHttp,
      headers
    });
    const wasm = await server$1.getContractWasmByHash(wasmHash, format);
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
    const spec$1 = await spec.Spec.fromWasm(wasm);
    return new Client(spec$1, options);
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
    const server$1 = new server.RpcServer(rpcUrl, {
      allowHttp,
      headers
    });
    const wasm = await server$1.getContractWasmByContractId(contractId);
    return Client.fromWasm(wasm, options);
  }
  txFromJSON = (json) => {
    const { method, ...tx } = JSON.parse(json);
    return assembled_transaction.AssembledTransaction.fromJSON(
      {
        ...this.options,
        method,
        parseResultXdr: (result) => this.spec.funcResToNative(method, result)
      },
      tx
    );
  };
  txFromXDR = (xdrBase64) => assembled_transaction.AssembledTransaction.fromXDR(this.options, xdrBase64, this.spec);
}

exports.Client = Client;
//# sourceMappingURL=client.js.map

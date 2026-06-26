'use strict';

var buffer = require('buffer');
var curr_generated = require('../generated/curr_generated.js');
var keypair = require('../keypair.js');
var address = require('../address.js');
var asset = require('../asset.js');
var operations = require('../util/operations.js');

function invokeHostFunction(opts) {
  if (!opts.func) {
    throw new TypeError(
      `host function invocation ('func') required (got ${JSON.stringify(opts)})`
    );
  }
  if (opts.func.switch().value === curr_generated.default.HostFunctionType.hostFunctionTypeInvokeContract().value) {
    opts.func.invokeContract().args().forEach((arg) => {
      let scv;
      try {
        scv = address.Address.fromScVal(arg);
      } catch {
        return;
      }
      switch (scv.type) {
        case "claimableBalance":
        case "liquidityPool":
          throw new TypeError(
            `claimable balances and liquidity pools cannot be arguments to invokeHostFunction`
          );
      }
    });
  }
  const invokeHostFunctionOp = new curr_generated.default.InvokeHostFunctionOp({
    hostFunction: opts.func,
    auth: opts.auth || []
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.invokeHostFunction(invokeHostFunctionOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function invokeContractFunction(opts) {
  const c = new address.Address(opts.contract);
  if (c.type !== "contract") {
    throw new TypeError(
      `expected contract strkey instance, got ${c.toString()}`
    );
  }
  return invokeHostFunction({
    func: curr_generated.default.HostFunction.hostFunctionTypeInvokeContract(
      new curr_generated.default.InvokeContractArgs({
        contractAddress: c.toScAddress(),
        functionName: opts.function,
        args: opts.args
      })
    ),
    ...opts.source !== void 0 && { source: opts.source },
    ...opts.auth !== void 0 && { auth: opts.auth }
  });
}
function createCustomContract(opts) {
  const salt = buffer.Buffer.from(opts.salt || getSalty());
  if (!opts.wasmHash || opts.wasmHash.length !== 32) {
    throw new TypeError(
      `expected hash(contract WASM) in 'opts.wasmHash', got ${String(opts.wasmHash)}`
    );
  }
  if (salt.length !== 32) {
    throw new TypeError(
      `expected 32-byte salt in 'opts.salt', got ${String(opts.salt)}`
    );
  }
  return invokeHostFunction({
    func: curr_generated.default.HostFunction.hostFunctionTypeCreateContractV2(
      new curr_generated.default.CreateContractArgsV2({
        executable: curr_generated.default.ContractExecutable.contractExecutableWasm(
          buffer.Buffer.from(opts.wasmHash)
        ),
        contractIdPreimage: curr_generated.default.ContractIdPreimage.contractIdPreimageFromAddress(
          new curr_generated.default.ContractIdPreimageFromAddress({
            address: opts.address.toScAddress(),
            salt
          })
        ),
        constructorArgs: opts.constructorArgs ?? []
      })
    ),
    ...opts.source !== void 0 && { source: opts.source },
    ...opts.auth !== void 0 && { auth: opts.auth }
  });
}
function createStellarAssetContract(opts) {
  let asset$1 = opts.asset;
  if (typeof asset$1 === "string") {
    const parts = asset$1.split(":");
    const code = parts[0];
    if (code === void 0) {
      throw new TypeError(
        `expected Asset in 'opts.asset', got ${String(opts.asset)}`
      );
    }
    asset$1 = new asset.Asset(code, parts[1]);
  }
  if (!(asset$1 instanceof asset.Asset)) {
    throw new TypeError(
      `expected Asset in 'opts.asset', got ${String(opts.asset)}`
    );
  }
  return invokeHostFunction({
    func: curr_generated.default.HostFunction.hostFunctionTypeCreateContract(
      new curr_generated.default.CreateContractArgs({
        executable: curr_generated.default.ContractExecutable.contractExecutableStellarAsset(),
        contractIdPreimage: curr_generated.default.ContractIdPreimage.contractIdPreimageFromAsset(
          asset$1.toXDRObject()
        )
      })
    ),
    auth: opts.auth || [],
    ...opts.source !== void 0 && { source: opts.source }
  });
}
function uploadContractWasm(opts) {
  return invokeHostFunction({
    func: curr_generated.default.HostFunction.hostFunctionTypeUploadContractWasm(
      buffer.Buffer.from(opts.wasm)
      // coalesce so we can drop `Buffer` someday
    ),
    auth: opts.auth || [],
    ...opts.source !== void 0 && { source: opts.source }
  });
}
function getSalty() {
  return keypair.Keypair.random().xdrPublicKey().value();
}

exports.createCustomContract = createCustomContract;
exports.createStellarAssetContract = createStellarAssetContract;
exports.invokeContractFunction = invokeContractFunction;
exports.invokeHostFunction = invokeHostFunction;
exports.uploadContractWasm = uploadContractWasm;
//# sourceMappingURL=invoke_host_function.js.map

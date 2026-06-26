import { Buffer } from 'buffer';
import types from '../generated/curr_generated.js';
import { Keypair } from '../keypair.js';
import { Address } from '../address.js';
import { Asset } from '../asset.js';
import { setSourceAccount } from '../util/operations.js';

function invokeHostFunction(opts) {
  if (!opts.func) {
    throw new TypeError(
      `host function invocation ('func') required (got ${JSON.stringify(opts)})`
    );
  }
  if (opts.func.switch().value === types.HostFunctionType.hostFunctionTypeInvokeContract().value) {
    opts.func.invokeContract().args().forEach((arg) => {
      let scv;
      try {
        scv = Address.fromScVal(arg);
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
  const invokeHostFunctionOp = new types.InvokeHostFunctionOp({
    hostFunction: opts.func,
    auth: opts.auth || []
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.invokeHostFunction(invokeHostFunctionOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function invokeContractFunction(opts) {
  const c = new Address(opts.contract);
  if (c.type !== "contract") {
    throw new TypeError(
      `expected contract strkey instance, got ${c.toString()}`
    );
  }
  return invokeHostFunction({
    func: types.HostFunction.hostFunctionTypeInvokeContract(
      new types.InvokeContractArgs({
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
  const salt = Buffer.from(opts.salt || getSalty());
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
    func: types.HostFunction.hostFunctionTypeCreateContractV2(
      new types.CreateContractArgsV2({
        executable: types.ContractExecutable.contractExecutableWasm(
          Buffer.from(opts.wasmHash)
        ),
        contractIdPreimage: types.ContractIdPreimage.contractIdPreimageFromAddress(
          new types.ContractIdPreimageFromAddress({
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
  let asset = opts.asset;
  if (typeof asset === "string") {
    const parts = asset.split(":");
    const code = parts[0];
    if (code === void 0) {
      throw new TypeError(
        `expected Asset in 'opts.asset', got ${String(opts.asset)}`
      );
    }
    asset = new Asset(code, parts[1]);
  }
  if (!(asset instanceof Asset)) {
    throw new TypeError(
      `expected Asset in 'opts.asset', got ${String(opts.asset)}`
    );
  }
  return invokeHostFunction({
    func: types.HostFunction.hostFunctionTypeCreateContract(
      new types.CreateContractArgs({
        executable: types.ContractExecutable.contractExecutableStellarAsset(),
        contractIdPreimage: types.ContractIdPreimage.contractIdPreimageFromAsset(
          asset.toXDRObject()
        )
      })
    ),
    auth: opts.auth || [],
    ...opts.source !== void 0 && { source: opts.source }
  });
}
function uploadContractWasm(opts) {
  return invokeHostFunction({
    func: types.HostFunction.hostFunctionTypeUploadContractWasm(
      Buffer.from(opts.wasm)
      // coalesce so we can drop `Buffer` someday
    ),
    auth: opts.auth || [],
    ...opts.source !== void 0 && { source: opts.source }
  });
}
function getSalty() {
  return Keypair.random().xdrPublicKey().value();
}

export { createCustomContract, createStellarAssetContract, invokeContractFunction, invokeHostFunction, uploadContractWasm };
//# sourceMappingURL=invoke_host_function.js.map

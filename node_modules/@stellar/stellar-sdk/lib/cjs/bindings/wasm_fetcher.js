'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
var curr_generated = require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
var strkey = require('../base/strkey.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
var address = require('../base/address.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var contract = require('../base/contract.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');

class WasmFetchError extends Error {
  constructor(message, cause) {
    super(message);
    this.cause = cause;
    this.name = "WasmFetchError";
  }
  cause;
}
async function getRemoteWasmFromHash(server, hashBuffer) {
  try {
    const contractCodeKey = curr_generated.default.LedgerKey.contractCode(
      new curr_generated.default.LedgerKeyContractCode({
        hash: curr_generated.default.Hash.fromXDR(hashBuffer, "raw")
      })
    );
    const response = await server.getLedgerEntries(contractCodeKey);
    if (!response.entries || response.entries.length === 0) {
      throw new WasmFetchError("WASM not found for the given hash");
    }
    const entry = response.entries[0];
    if (entry.key.switch() !== curr_generated.default.LedgerEntryType.contractCode()) {
      throw new WasmFetchError("Invalid ledger entry type returned");
    }
    const contractCode = entry.val.contractCode();
    return buffer.Buffer.from(contractCode.code());
  } catch (error) {
    if (error instanceof WasmFetchError) {
      throw error;
    }
    throw new WasmFetchError("Failed to fetch WASM from hash", error);
  }
}
function isStellarAssetContract(instance) {
  return instance.executable().switch() === curr_generated.default.ContractExecutableType.contractExecutableStellarAsset();
}
async function fetchWasmFromContract(server, contractAddress) {
  try {
    const contract$1 = new contract.Contract(contractAddress.toString());
    const response = await server.getLedgerEntries(contract$1.getFootprint());
    if (!response.entries || response.entries.length === 0) {
      throw new WasmFetchError("Contract instance not found");
    }
    const entry = response.entries[0];
    if (entry.key.switch() !== curr_generated.default.LedgerEntryType.contractData()) {
      throw new WasmFetchError("Invalid ledger entry type returned");
    }
    const contractData = entry.val.contractData();
    const instance = contractData.val().instance();
    if (isStellarAssetContract(instance)) {
      return { type: "stellar-asset-contract" };
    }
    const wasmHash = instance.executable().wasmHash();
    const wasmBytes = await getRemoteWasmFromHash(server, wasmHash);
    return { type: "wasm", wasmBytes };
  } catch (error) {
    if (error instanceof WasmFetchError) {
      throw error;
    }
    throw new WasmFetchError(
      "Failed to fetch WASM from contract",
      error
    );
  }
}
async function fetchFromWasmHash(wasmHash, rpcServer) {
  try {
    const hashBuffer = buffer.Buffer.from(wasmHash, "hex");
    if (hashBuffer.length !== 32) {
      throw new WasmFetchError(
        `Invalid WASM hash length: expected 32 bytes, got ${hashBuffer.length}`
      );
    }
    const wasmBytes = await getRemoteWasmFromHash(rpcServer, hashBuffer);
    return { type: "wasm", wasmBytes };
  } catch (error) {
    throw new WasmFetchError(
      `Failed to fetch WASM from hash ${wasmHash}`,
      error
    );
  }
}
async function fetchFromContractId(contractId, rpcServer) {
  try {
    if (!strkey.StrKey.isValidContract(contractId)) {
      throw new WasmFetchError(`Invalid contract ID: ${contractId}`);
    }
    const contractAddress = address.Address.fromString(contractId);
    return await fetchWasmFromContract(rpcServer, contractAddress);
  } catch (error) {
    throw new WasmFetchError(
      `Failed to fetch WASM from contract ${contractId}`,
      error
    );
  }
}

exports.WasmFetchError = WasmFetchError;
exports.fetchFromContractId = fetchFromContractId;
exports.fetchFromWasmHash = fetchFromWasmHash;
//# sourceMappingURL=wasm_fetcher.js.map

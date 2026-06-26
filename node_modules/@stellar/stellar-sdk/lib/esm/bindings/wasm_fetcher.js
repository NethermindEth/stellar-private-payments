import { Buffer } from 'buffer';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import types from '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import { StrKey } from '../base/strkey.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import { Address } from '../base/address.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import { Contract } from '../base/contract.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';

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
    const contractCodeKey = types.LedgerKey.contractCode(
      new types.LedgerKeyContractCode({
        hash: types.Hash.fromXDR(hashBuffer, "raw")
      })
    );
    const response = await server.getLedgerEntries(contractCodeKey);
    if (!response.entries || response.entries.length === 0) {
      throw new WasmFetchError("WASM not found for the given hash");
    }
    const entry = response.entries[0];
    if (entry.key.switch() !== types.LedgerEntryType.contractCode()) {
      throw new WasmFetchError("Invalid ledger entry type returned");
    }
    const contractCode = entry.val.contractCode();
    return Buffer.from(contractCode.code());
  } catch (error) {
    if (error instanceof WasmFetchError) {
      throw error;
    }
    throw new WasmFetchError("Failed to fetch WASM from hash", error);
  }
}
function isStellarAssetContract(instance) {
  return instance.executable().switch() === types.ContractExecutableType.contractExecutableStellarAsset();
}
async function fetchWasmFromContract(server, contractAddress) {
  try {
    const contract = new Contract(contractAddress.toString());
    const response = await server.getLedgerEntries(contract.getFootprint());
    if (!response.entries || response.entries.length === 0) {
      throw new WasmFetchError("Contract instance not found");
    }
    const entry = response.entries[0];
    if (entry.key.switch() !== types.LedgerEntryType.contractData()) {
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
    const hashBuffer = Buffer.from(wasmHash, "hex");
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
    if (!StrKey.isValidContract(contractId)) {
      throw new WasmFetchError(`Invalid contract ID: ${contractId}`);
    }
    const contractAddress = Address.fromString(contractId);
    return await fetchWasmFromContract(rpcServer, contractAddress);
  } catch (error) {
    throw new WasmFetchError(
      `Failed to fetch WASM from contract ${contractId}`,
      error
    );
  }
}

export { WasmFetchError, fetchFromContractId, fetchFromWasmHash };
//# sourceMappingURL=wasm_fetcher.js.map

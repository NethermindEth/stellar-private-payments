import init, {
  Client as WasmClient,
  PrivatePool,
  Storage as WasmStorage,
  bootnodeRequired as wasmBootnodeRequired,
  verifySelectiveDisclosure as wasmVerifySelectiveDisclosure,
} from '../dist/stellar_private_payments_sdk_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

/**
 * Open worker-backed local persistence. Prefer one `Storage.open()` per page,
 * then pass the instance (or a fork) to {@link Client.new}.
 */
async function openStorage(options = {}) {
  return WasmStorage.open({
    workerUrl: options.workerUrl ?? storageWorkerUrl,
  });
}

/**
 * Probe whether the wallet RPC needs a historical-sync bootnode.
 * @param {string} rpcUrl
 * @param {import('../dist/stellar_private_payments_sdk_web.js').Storage} storage
 * @returns {Promise<boolean>}
 */
async function bootnodeRequired(rpcUrl, storage) {
  return wasmBootnodeRequired(rpcUrl, storage);
}

function wrapAccount(wasmAccount) {
  return {
    get userAddress() {
      return wasmAccount.userAddress;
    },
    portfolio: () => wasmAccount.portfolio(),
    userPublicKeys: () => wasmAccount.userPublicKeys(),
    aspSecret: () => wasmAccount.aspSecret(),
    userNotes: (limit) => wasmAccount.userNotes(limit),
    isRegistered: () => wasmAccount.isRegistered(),
    deriveAspUserLeaf: (options) => wasmAccount.deriveAspUserLeaf(options),
    registerPublicKeys: (options) => wasmAccount.registerPublicKeys(options),
    pool: (options) => wasmAccount.pool(options),
  };
}

function wrapClient(wasmClient) {
  return {
    backgroundSync: () => wasmClient.backgroundSync(),
    stopBackgroundSync: () => wasmClient.stopBackgroundSync(),
    sync: () => wasmClient.sync(),
    operationalFeed: (limit) => wasmClient.operationalFeed(limit),
    account: async (options, signer) => {
      const userAddress =
        options.userAddress ??
        (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

      if (!userAddress) {
        throw new Error('options.userAddress is required (or signer must implement getPublicKey)');
      }

      const wasmAccount = await wasmClient.account(
        {
          ...options,
          userAddress,
        },
        signer,
      );
      return wrapAccount(wasmAccount);
    },
    recipientLookup: (address) => wasmClient.recipientLookup(address),
    aspState: () => wasmClient.aspState(),
    allContractsData: () => wasmClient.allContractsData(),
    verifySelectiveDisclosure: (receiptJson, expectedVkHash) =>
      wasmClient.verifySelectiveDisclosure(receiptJson, expectedVkHash),
  };
}

/**
 * Create a deployment client. Call {@link bootnodeRequired} (configure bootnode
 * if needed), then `backgroundSync`, then `account` before pool ops.
 *
 * When `options.storage` is omitted, opens a default storage worker automatically.
 * Prover worker URL defaults to the package `dist/workers/` via `import.meta.url`.
 */
async function newClient(options) {
  const storage =
    options.storage ??
    (await openStorage({
      workerUrl: options.storageWorkerUrl ?? storageWorkerUrl,
    }));

  return wrapClient(
    await WasmClient.new(
      options.rpcUrl,
      storage,
      options.proverWorkerUrl ?? proverWorkerUrl,
      options.bootnodeUrl ?? undefined,
    ),
  );
}

/**
 * Walletless selective-disclosure verification (no storage / Client).
 * Prover worker URL defaults to the package `dist/workers/` via `import.meta.url`.
 */
function verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, options = {}) {
  return wasmVerifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, {
    proverWorkerUrl,
    ...options,
  });
}

export const Storage = { open: openStorage };
export const Client = {
  new: newClient,
  contractConfig: WasmClient.contractConfig,
};
export { PrivatePool, bootnodeRequired, verifySelectiveDisclosure };
export { default } from '../dist/stellar_private_payments_sdk_web.js';
export { FreighterSigner } from './freighter.js';

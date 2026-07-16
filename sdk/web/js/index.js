import init, {
  Client as WasmClient,
  PrivatePool,
  Storage as WasmStorage,
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
    checkSync: (options) => wasmClient.checkSync(options),
    startSync: (options) => wasmClient.startSync(options),
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
 * Create a deployment client. Call `startSync` then `account` before pool ops.
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
    ),
  );
}

export const Storage = { open: openStorage };
export const Client = {
  new: newClient,
  contractConfig: WasmClient.contractConfig,
};
export { PrivatePool };
export { default } from '../dist/stellar_private_payments_sdk_web.js';
export { FreighterSigner } from './freighter.js';

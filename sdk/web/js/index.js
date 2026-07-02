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

function wrapClient(wasmClient) {
  return {
    checkEventSync: (options) => wasmClient.checkEventSync(options),
    startEventSync: (options) => wasmClient.startEventSync(options),
    initialize: async (options, signer) => {
      const userAddress =
        options.userAddress ??
        (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

      if (!userAddress) {
        throw new Error('options.userAddress is required (or signer must implement getPublicKey)');
      }

      return wasmClient.initialize(
        {
          proverWorkerUrl,
          ...options,
          userAddress,
        },
        signer,
      );
    },
    registerPublicKeys: (options) => wasmClient.registerPublicKeys(options),
    lookupRegisteredPublicKey: (address) => wasmClient.lookupRegisteredPublicKey(address),
    allContractsData: () => wasmClient.allContractsData(),
    verifySelectiveDisclosure: (receiptJson, expectedVkHash, options = {}) =>
      wasmClient.verifySelectiveDisclosure(receiptJson, expectedVkHash, {
        proverWorkerUrl,
        ...options,
      }),
    pool: (options) => wasmClient.pool(options),
  };
}

/**
 * Create a client shell. Call `startEventSync` then `initialize` before pool ops.
 *
 * When `options.storage` is omitted, opens a default storage worker automatically.
 */
async function newClient(options) {
  const storage =
    options.storage ??
    (await openStorage({
      workerUrl: options.storageWorkerUrl ?? storageWorkerUrl,
    }));

  return wrapClient(await WasmClient.new(storage, options.rpcUrl));
}

export const Storage = { open: openStorage };
export const Client = { new: newClient, contractConfig: WasmClient.contractConfig };
export { PrivatePool };
export { default } from '../dist/stellar_private_payments_sdk_web.js';
export { FreighterSigner } from './freighter.js';

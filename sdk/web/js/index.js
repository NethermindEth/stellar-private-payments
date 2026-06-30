import init, {
  Client as WasmClient,
  PrivatePool,
  Storage as WasmStorage,
} from '../dist/private_payments_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

/**
 * Open worker-backed local persistence. Prefer one `Storage.open()` per page,
 * then pass the instance (or a fork) to {@link Client.connect}.
 */
async function openStorage(options = {}) {
  return WasmStorage.open({
    workerUrl: options.workerUrl ?? storageWorkerUrl,
  });
}

/**
 * Connect a wallet session. `options.userAddress` is optional when
 * `signer.getPublicKey()` exists (e.g. `FreighterSigner`).
 *
 * When `options.storage` is omitted, opens a default storage worker automatically.
 */
async function connect(options, signer) {
  const userAddress =
    options.userAddress ??
    (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

  if (!userAddress) {
    throw new Error('options.userAddress is required (or signer must implement getPublicKey)');
  }

  const storage =
    options.storage ??
    (await openStorage({
      workerUrl: options.storageWorkerUrl ?? storageWorkerUrl,
    }));

  return WasmClient.connect(
    {
      proverWorkerUrl,
      ...options,
      userAddress,
      storage,
    },
    signer,
  );
}

export const Storage = { open: openStorage };
export const Client = { connect, contractConfig: WasmClient.contractConfig };
export { PrivatePool };
export { default } from '../dist/private_payments_web.js';
export { FreighterSigner } from './freighter.js';

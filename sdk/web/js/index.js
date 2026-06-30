import init, { Client as WasmClient, PrivatePool } from '../dist/private_payments_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

/**
 * Connect a wallet session. `options.userAddress` is optional when
 * `signer.getPublicKey()` exists (e.g. `FreighterSigner`).
 */
async function connect(options, signer) {
  const userAddress =
    options.userAddress ??
    (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

  if (!userAddress) {
    throw new Error('options.userAddress is required (or signer must implement getPublicKey)');
  }

  return WasmClient.connect(
    {
      storageWorkerUrl,
      proverWorkerUrl,
      ...options,
      userAddress,
    },
    signer,
  );
}

export const Client = { connect, contractConfig: WasmClient.contractConfig };
export { PrivatePool };
export { default } from '../dist/private_payments_web.js';
export { FreighterSigner } from './freighter.js';

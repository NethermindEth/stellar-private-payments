import init, {
  PrivatePool as WasmPrivatePool,
  contractConfig as contractConfigWasm,
  allContractsData as allContractsDataWasm,
  lookupRegisteredPublicKey as lookupRegisteredPublicKeyWasm,
  initialize as initializeWasm,
  registerPublicKeys as registerPublicKeysWasm,
} from '../dist/private_payments_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

const workerDefaults = { storageWorkerUrl, proverWorkerUrl };

/**
 * Open a private pool session. Pass a wallet signer as the second argument
 * (`FreighterSigner` or any object with `signMessage`, `signTransaction`,
 * `signAuthEntry`).
 *
 * `config.userAddress` is optional when `signer.getPublicKey()` exists.
 */
async function createPool(config, signer) {
  const userAddress =
    config.userAddress ??
    (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

  if (!userAddress) {
    throw new Error('config.userAddress is required (or signer must implement getPublicKey)');
  }

  return WasmPrivatePool.new(
    {
      ...workerDefaults,
      ...config,
      userAddress,
    },
    signer,
  );
}

export const PrivatePool = { new: createPool };

export function contractConfig() {
  return contractConfigWasm();
}

export function allContractsData(rpcUrl) {
  return allContractsDataWasm(rpcUrl);
}

export function lookupRegisteredPublicKey(config) {
  return lookupRegisteredPublicKeyWasm({ ...workerDefaults, ...config });
}

export function initialize(config, signer) {
  return initializeWasm({ ...workerDefaults, ...config }, signer);
}

export function registerPublicKeys(config, signer) {
  return registerPublicKeysWasm({ ...workerDefaults, ...config }, signer);
}

export { default } from '../dist/private_payments_web.js';
export { FreighterSigner } from './freighter.js';

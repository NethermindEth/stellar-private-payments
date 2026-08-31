import init, {
  Client as WasmClient,
  PrivatePool,
  Storage as WasmStorage,
  bootnodeRequired as wasmBootnodeRequired,
  deriveAspUserLeaf as wasmDeriveAspUserLeaf,
  verifySelectiveDisclosure as wasmVerifySelectiveDisclosure,
  configureTelemetry,
  set_log_level,
  dump_recent_logs,
  debugLogsEnabled,
} from '../dist/stellar_private_payments_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

function requireField(value, name) {
  if (value === undefined || value === null) {
    throw new Error(`${name} is required`);
  }
  return value;
}

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
 * @param {import('../dist/stellar_private_payments_web.js').Storage} storage
 * @param {{ contractConfig: unknown }} options
 * @returns {Promise<boolean>}
 */
async function bootnodeRequired(rpcUrl, storage, options) {
  return wasmBootnodeRequired(
    rpcUrl,
    storage,
    requireField(options?.contractConfig, 'contractConfig'),
  );
}

/**
 * Derive the ASP membership leaf from explicit public inputs.
 * @param {string} notePublicKey `0x`-prefixed 32-byte hex
 * @param {string} membershipBlinding `0x`-prefixed 32-byte hex field
 * @returns {string} leaf as `0x` hex
 */
function deriveAspUserLeaf(notePublicKey, membershipBlinding) {
  return wasmDeriveAspUserLeaf(notePublicKey, membershipBlinding);
}

function wrapAccount(wasmAccount) {
  return {
    get userAddress() {
      return wasmAccount.userAddress;
    },
    get signerAddress() {
      return wasmAccount.signerAddress;
    },
    portfolio: () => wasmAccount.portfolio(),
    userPublicKeys: () => wasmAccount.userPublicKeys(),
    aspSecret: () => wasmAccount.aspSecret(),
    userNotes: (limit) => wasmAccount.userNotes(limit),
    isRegistered: () => wasmAccount.isRegistered(),
    deriveAspUserLeaf: () => wasmAccount.deriveAspUserLeaf(),
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
    contractConfig: () => wasmClient.contractConfig(),
    account: async (options, signer) => {
      const userAddress =
        options.userAddress ??
        (typeof signer?.getPublicKey === 'function' ? await signer.getPublicKey() : undefined);

      if (!userAddress) {
        throw new Error('options.userAddress is required (or signer must implement getPublicKey)');
      }

      if (options.signerAddress && !options.userAddress) {
        throw new Error(
          'options.userAddress is required when options.signerAddress is supplied',
        );
      }
      const signerAddress = options.signerAddress ?? userAddress;

      const wasmAccount = await wasmClient.account(
        {
          ...options,
          userAddress,
          signerAddress,
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
 */
async function newClient(options) {
  const contractConfig = requireField(options.contractConfig, 'contractConfig');
  const circuitsBaseUrl = requireField(options.circuitsBaseUrl, 'circuitsBaseUrl');

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
      contractConfig,
      circuitsBaseUrl,
      options.bootnodeUrl ?? undefined,
    ),
  );
}

/**
 * Walletless selective-disclosure verification (no storage / Client).
 */
function verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, options) {
  requireField(options?.contractConfig, 'contractConfig');
  requireField(options?.circuitsBaseUrl, 'circuitsBaseUrl');
  return wasmVerifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, {
    proverWorkerUrl,
    ...options,
  });
}

export const Storage = { open: openStorage };
export const Client = {
  new: newClient,
};
export { PrivatePool, bootnodeRequired, deriveAspUserLeaf, verifySelectiveDisclosure };
export { configureTelemetry, set_log_level, dump_recent_logs, debugLogsEnabled };
export { default } from '../dist/stellar_private_payments_web.js';

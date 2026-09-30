import init, {
  Client as WasmClient,
  DisclosureRequest,
  Storage as WasmStorage,
  ProverBridge,
  WalletSigner as WasmWalletSigner,
  bootnodeRequired as wasmBootnodeRequired,
  deriveAspUserLeaf as wasmDeriveAspUserLeaf,
  verifySelectiveDisclosure as wasmVerifySelectiveDisclosure,
  configureTelemetry,
  set_log_level,
  dump_recent_logs,
  debugLogsEnabled,
  registerTelemetrySinks,
} from '../dist/stellar_private_payments_web.js';

const storageWorkerUrl = new URL('../dist/workers/storage-worker.js', import.meta.url).href;
const proverWorkerUrl = new URL('../dist/workers/prover-worker.js', import.meta.url).href;

/** @type {'stellar-private-payments:tx-progress'} */
export const TX_PROGRESS_EVENT = 'stellar-private-payments:tx-progress';

/**
 * Frees a client's telemetry sinks once the client itself is garbage
 * collected, so forgetting to call `dispose()` leaks a GC cycle at worst
 * instead of leaking forever.
 */
const telemetryFinalizer = new FinalizationRegistry((telemetrySinks) => telemetrySinks.free());

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

function wrapClient(wasmClient, telemetrySinks) {
  return {
    backgroundSync: () => wasmClient.backgroundSync(),
    stopBackgroundSync: () => wasmClient.stopBackgroundSync(),
    /**
     * Free this client's telemetry sinks now, instead of waiting for GC to
     * do it. Optional — {@link newClient} already registers the client for
     * automatic cleanup.
     */
    dispose: () => {
      telemetryFinalizer.unregister(wasmClient);
      telemetrySinks.free();
      wasmClient.free();
    },
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
      const networkPassphrase = requireField(options.networkPassphrase, 'networkPassphrase');
      const walletSigner = new WasmWalletSigner(signer, networkPassphrase, signerAddress);
      const signerHandle = walletSigner.toHandle();
      try {
        return await wasmClient.account(userAddress, signerHandle);
      } finally {
        signerHandle.free();
        walletSigner.free();
      }
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

  const storage =
    options.storage ??
    (await openStorage({
      workerUrl: options.storageWorkerUrl ?? storageWorkerUrl,
    }));

  let prover = options.prover;
  if (!prover) {
    const circuitsBaseUrl = requireField(options.circuitsBaseUrl, 'circuitsBaseUrl');
    const resolvedProverWorkerUrl = options.proverWorkerUrl ?? proverWorkerUrl;
    if (!resolvedProverWorkerUrl.trim()) {
      throw new Error('proverWorkerUrl is required (absolute URL to prover-worker.js)');
    }
    prover = ProverBridge.spawn(resolvedProverWorkerUrl);
    await prover.configureCircuitsBase(circuitsBaseUrl);
    await prover.ping();
  }
  const proverHandle = prover.toHandle();
  const storageHandle = await storage.toHandle();
  const telemetrySinks = registerTelemetrySinks(storage.fork(), prover.fork());

  try {
    const wasmClient = await WasmClient.new(
      options.rpcUrl,
      storageHandle,
      proverHandle,
      contractConfig,
      options.bootnodeUrl ?? undefined,
    );
    telemetryFinalizer.register(wasmClient, telemetrySinks);
    return wrapClient(wasmClient, telemetrySinks);
  } finally {
    storageHandle.free();
    proverHandle.free();
  }
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
export { DisclosureRequest, ProverBridge, bootnodeRequired, deriveAspUserLeaf, verifySelectiveDisclosure };
export {
  configureTelemetry,
  set_log_level,
  dump_recent_logs,
  debugLogsEnabled,
};
export { default } from '../dist/stellar_private_payments_web.js';

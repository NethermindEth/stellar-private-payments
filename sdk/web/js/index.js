import init, {
  Client as WasmClient,
  AllowlistOperator,
  BlocklistOperator,
  PoolAdmin,
  DisclosureRequest,
  readTokenDecimals,
  parseTokenAmount as wasmParseTokenAmount,
  Storage as WasmStorage,
  ProverBridge,
  WalletSigner as WasmWalletSigner,
  bootnodeRequired as wasmBootnodeRequired,
  verifySelectiveDisclosure as wasmVerifySelectiveDisclosure,
  configureTelemetry,
  set_log_level,
  dump_recent_logs,
  debugLogsEnabled,
  registerTelemetrySinks,
} from '../dist/stellar_private_payments_web.js';
// Written by build.sh: the threaded prover worker's URL, or null if this build has none.
import { threadedProverWorkerUrl } from '../dist/prover-threads.js';

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

/** Parse token units exactly into bigint base units. */
function parseTokenAmount(value, decimals) {
  if (typeof value !== 'string') throw new TypeError('Amount must be a string');
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 0xffff_ffff) {
    throw new RangeError('Decimals must be a u32 integer');
  }
  return wasmParseTokenAmount(value, decimals);
}

/**
 * Validate `proverThreads`. Returns null for automatic, otherwise the most
 * threads the prover may use; 1 means the serial worker.
 */
function parseProverThreads(value) {
  if (value === undefined || value === true) return null;
  if (value === false) return 1;
  if (typeof value !== 'number') throw new TypeError('proverThreads must be a boolean or a number');
  if (!Number.isInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new RangeError('proverThreads must be a positive integer (u32)');
  }
  return value;
}

/** Whether this page lets a worker share its memory with other workers. */
function canShareMemory() {
  return globalThis.crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';
}

/**
 * Spawn a prover worker and configure its circuits. Resolves to the bridge and
 * how it proves: `{ mode: 'serial' | 'threaded' | 'custom', threads }`.
 *
 * The threaded worker is used only if this build has one, the page is
 * cross-origin isolated and `proverThreads` allows it. If it does not start,
 * the serial worker takes over, so a proof never fails for want of threads. An
 * explicit `proverWorkerUrl` is spawned as given, with no thread selection.
 */
async function spawnProver(options, circuitsBaseUrl, lockJson) {
  const requested = parseProverThreads(options?.proverThreads);

  // Takes ownership of `prover`: frees it if it cannot be configured.
  async function configure(prover, info) {
    try {
      await prover.configureCircuitsBase(circuitsBaseUrl, lockJson);
      await prover.ping();
    } catch (error) {
      prover.free();
      throw error;
    }
    return { prover, info };
  }

  if (options?.proverWorkerUrl != null) {
    if (!options.proverWorkerUrl.trim()) {
      throw new Error('proverWorkerUrl is required (absolute URL to prover-worker.js)');
    }
    return configure(ProverBridge.spawn(options.proverWorkerUrl), { mode: 'custom', threads: null });
  }

  const wanted = requested ?? (Math.trunc(globalThis.navigator?.hardwareConcurrency) || 1);
  if (threadedProverWorkerUrl && canShareMemory() && wanted > 1) {
    const threaded = ProverBridge.spawn(threadedProverWorkerUrl);
    let threads;
    try {
      // The worker clamps to its core count and answers with the size it will use.
      threads = await threaded.configureThreads(wanted);
    } catch (error) {
      threaded.free();
      console.warn('[stellar-private-payments] threaded prover worker unavailable, proving on one thread:', error);
    }
    if (threads !== undefined) {
      return configure(threaded, { mode: 'threaded', threads });
    }
  }

  return configure(ProverBridge.spawn(proverWorkerUrl), { mode: 'serial', threads: 1 });
}

function requireField(value, name) {
  if (value === undefined || value === null) {
    throw new Error(`${name} is required`);
  }
  return value;
}

/**
 * Open encrypted worker-backed persistence with a required key provider,
 * then pass the instance (or a fork) to {@link Client.new}.
 */
async function openStorage(options) {
  // Fail before the provider can prompt for a signature or persist a key.
  if (!WasmStorage.encryptedStorageEnabled()) {
    throw new Error('Encrypted storage requires a build with the encrypted-storage feature');
  }
  const provider = requireField(options?.keyProvider, 'keyProvider');
  if (typeof provider !== 'function') throw new TypeError('keyProvider must be a function');
  const createNew = options.createNew === true;
  const supplied = await provider('spp.encrypted.db', createNew ? 'create' : 'open');
  if (!ArrayBuffer.isView(supplied) || Object.prototype.toString.call(supplied) !== '[object Uint8Array]' || supplied.byteLength !== 32) {
    throw new TypeError('keyProvider must return a 32-byte Uint8Array');
  }
  // Leave the provider's own buffer intact; clear the copy owned by this call.
  const transport = new Uint8Array(supplied);
  try {
    return await WasmStorage.open({ workerUrl: options.workerUrl ?? storageWorkerUrl, key: transport, createNew, directory: options.directory });
  } finally {
    transport.fill(0);
  }
}

/**
 * Open plaintext worker-backed persistence (`spp.db`). Only available in
 * builds with the `unencrypted-storage` Cargo feature.
 */
async function openPlaintextStorage(options) {
  if (typeof WasmStorage.openPlaintext !== 'function') {
    throw new Error('Unencrypted storage requires a build with the unencrypted-storage feature');
  }
  return await WasmStorage.openPlaintext(options?.workerUrl ?? storageWorkerUrl);
}

/**
 * Probe whether the wallet RPC needs a historical-sync bootnode.
 * @param {string} rpcUrl
 * @param {import('../dist/stellar_private_payments_web.js').Storage} storage
 * @param {{ contractConfig: unknown }} options
 * @returns {Promise<boolean>}
 */
async function bootnodeRequired(rpcUrl, storage, options) {
  const contractConfig = requireField(options?.contractConfig, 'contractConfig');
  const storageHandle = await storage.toHandle();
  try {
    return await wasmBootnodeRequired(rpcUrl, storageHandle, contractConfig);
  } finally {
    storageHandle.free();
  }
}

function wrapClient(wasmClient, telemetrySinks, proverInfo) {
  return {
    /** How proofs run: `{ mode: 'serial' | 'threaded' | 'custom', threads }`. */
    proverInfo: () => ({ ...proverInfo }),
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
    allowlistIds: () => wasmClient.allowlistIds(),
    blocklistIds: () => wasmClient.blocklistIds(),
    poolIds: () => wasmClient.poolIds(),
    allowlistOperator: (contractId) => wasmClient.allowlistOperator(contractId),
    blocklistOperator: (contractId) => wasmClient.blocklistOperator(contractId),
    poolAdmin: (contractId) => wasmClient.poolAdmin(contractId),
    gvkAuthority: (globalViewPrivateKeyHex) => wasmClient.gvkAuthority(globalViewPrivateKeyHex),
    noteKeyOwnerLookup: (noteKeys) => wasmClient.noteKeyOwnerLookup(noteKeys),
    allContractsData: () => wasmClient.allContractsData(),
    poolContractsData: (poolContractId) => wasmClient.poolContractsData(poolContractId),
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
  const lockJson = options.prover ? undefined : JSON.stringify(requireField(options.circuitLock, 'circuitLock'));

  const storage =
    options.storage ??
    (await openStorage({
      workerUrl: options.storageWorkerUrl ?? storageWorkerUrl,
      keyProvider: options.keyProvider,
      createNew: options.createNew,
    }));

  let prover = options.prover;
  let proverInfo = { mode: 'custom', threads: null };
  if (!prover) {
    const circuitsBaseUrl = requireField(options.circuitsBaseUrl, 'circuitsBaseUrl');
    ({ prover, info: proverInfo } = await spawnProver(options, circuitsBaseUrl, lockJson));
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
    return wrapClient(wasmClient, telemetrySinks, proverInfo);
  } finally {
    storageHandle.free();
    proverHandle.free();
  }
}

/**
 * Walletless selective-disclosure verification (no storage / Client).
 */
async function verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, options) {
  const contractConfig = requireField(options?.contractConfig, 'contractConfig');
  const circuitsBaseUrl = requireField(options?.circuitsBaseUrl, 'circuitsBaseUrl');
  const lockJson = JSON.stringify(requireField(options?.circuitLock, 'circuitLock'));

  const { prover } = await spawnProver(options, circuitsBaseUrl, lockJson);
  try {
    const proverHandle = prover.toHandle();
    try {
      return await wasmVerifySelectiveDisclosure(rpcUrl, proverHandle, receiptJson, expectedVkHash, {
        contractConfig,
      });
    } finally {
      proverHandle.free();
    }
  } finally {
    prover.free();
  }
}

export const Storage = { open: openStorage, openPlaintext: openPlaintextStorage };
export const Client = {
  new: newClient,
};
export { AllowlistOperator, BlocklistOperator, PoolAdmin, DisclosureRequest, readTokenDecimals, parseTokenAmount, ProverBridge, bootnodeRequired, verifySelectiveDisclosure };
export {
  configureTelemetry,
  set_log_level,
  dump_recent_logs,
  debugLogsEnabled,
};
export { default } from '../dist/stellar_private_payments_web.js';

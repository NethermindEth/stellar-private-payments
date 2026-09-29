import { closeAndReload } from './storage-lock.js';
import { withStorageActivity } from './storage-activity.js';
/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, `Account`, and app persistence.
 *
 * Lifecycle: `bootnodeCheck` / `bootnodeRequired` → `initializeRuntime` →
 * `client().backgroundSync` → `client().openAccount` → `account().pool`.
 *
 * Privacy key reads use the SDK (`account().privacyKeys`, `account().aspSecret`, etc.).
 * App-only persistence (disclaimer, explorer, bootnode, op history, key probe) stays on `storage()`.
 */

import init, {
  Client,
  DisclosureRequest,
  Storage,
  bootnodeRequired as sdkBootnodeRequired,
  deriveAspUserLeaf as sdkDeriveAspUserLeaf,
  verifySelectiveDisclosure as sdkVerifySelectiveDisclosure,
  configureTelemetry,
  dump_recent_logs,
  debugLogsEnabled as sdkDebugLogsEnabled,
} from 'stellar-private-payments';
import { FreighterSigner } from 'stellar-private-payments/freighter';

import { AppStorage } from './app-storage.js';
import { startAutoLock, unlockStorage } from './storage-access.js';

export { DisclosureRequest };

const DEPLOYMENT_CONFIG_URL = new URL('./deployments.json', document.baseURI).href;
const CIRCUITS_BASE_URL = new URL(
  './js/stellar-private-payments/dist/circuits/',
  window.location.href,
).href;

/** Dispatched on `window` once the local database has been unlocked. */
export const STORAGE_UNLOCKED_EVENT = 'spp:storage-unlocked';

let storageHandle = null;
let storageOpening = null;
let privateOpening = null;
let privateUnlocked = false;
let stopAutoLock = null;
let appStorageInstance = null;
let wrappedClient = null;
let boundAccount = null;
let wasmReady = false;
let currentRpcUrl = null;
let currentBootnodeUrl = null;
let boundUserAddress = null;
let boundSignerAddress = null;
let deploymentConfigPromise = null;

export async function ensureWasmInit() {
    if (!wasmReady) {
        await init();
        wasmReady = true;
    }
}

/** Load the app deployment config served at `/deployments.json`. */
export async function loadDeploymentConfig() {
    if (!deploymentConfigPromise) {
        deploymentConfigPromise = fetch(DEPLOYMENT_CONFIG_URL)
            .then(async (res) => {
                if (!res.ok) {
                    throw new Error(
                        `failed to load deployment config from ${DEPLOYMENT_CONFIG_URL}`,
                    );
                }
                return res.json();
            })
            .catch((err) => {
                deploymentConfigPromise = null;
                throw err;
            });
    }
    return deploymentConfigPromise;
}

export function circuitsBaseUrl() {
    return CIRCUITS_BASE_URL;
}

function bindAppStorage(sdkStorage) {
    appStorageInstance = new AppStorage(sdkStorage, ensurePrivateStorage);
}

function wrapSdkClient(sdk) {
    return {
        ...sdk,
        contractConfig() {
            return sdk.contractConfig();
        },
        storage() {
            if (!appStorageInstance) {
                throw new Error('Storage not ready. Call ensureStorage or initializeRuntime first.');
            }
            return appStorageInstance;
        },
        async backgroundSync() {
            await sdk.backgroundSync();
        },
        async sync() {
            await withStorageActivity(() => sdk.sync());
        },
        stopBackgroundSync() {
            sdk.stopBackgroundSync();
        },
        async openAccount(
            { networkPassphrase, userAddress, signerAddress },
            signer = new FreighterSigner(),
        ) {
            await ensurePrivateStorage();
            const effectiveSigner = signerAddress ?? userAddress;
            if (
                boundUserAddress === userAddress &&
                boundSignerAddress === effectiveSigner &&
                boundAccount
            ) {
                return boundAccount;
            }

            boundAccount = await withStorageActivity(() => sdk.account(
                {
                    networkPassphrase,
                    userAddress,
                    signerAddress: effectiveSigner,
                },
                signer,
            ));
            boundUserAddress = userAddress;
            boundSignerAddress = effectiveSigner;
            return boundAccount;
        },
        account() {
            if (!boundAccount) {
                throw new Error('Account session not open. Call openAccount() first.');
            }
            return {
                portfolio: () => boundAccount.portfolio(),
                privacyKeys: () => boundAccount.privacyKeys(),
                derivePrivacyKeys: () => withStorageActivity(() => boundAccount.derivePrivacyKeys()),
                aspSecret: () => boundAccount.aspSecret(),
                userNotes: (limit) => boundAccount.userNotes(limit),
                isRegistered: () => boundAccount.isRegistered(),
                registerPublicKeys: () => withStorageActivity(() => boundAccount.registerPublicKeys()),
                deriveAspUserLeaf: () => boundAccount.deriveAspUserLeaf(),
                pool: (options) => boundAccount.pool(options),
            };
        },
    };
}

async function openWrappedClient(sdkStorage, rpcUrl, bootnodeUrl) {
    const contractConfig = await loadDeploymentConfig();
    const sdk = await Client.new({
        storage: sdkStorage,
        rpcUrl,
        bootnodeUrl: bootnodeUrl ?? undefined,
        contractConfig,
        circuitsBaseUrl: circuitsBaseUrl(),
    });
    return wrapSdkClient(sdk);
}

/** Stop background sync and drop the in-memory client/account (e.g. disconnect or rebuild). */
export function disposeClient() {
    try {
        wrappedClient?.stopBackgroundSync?.();
    } catch {
        // Client may already be tearing down.
    }
    wrappedClient = null;
    boundAccount = null;
    boundUserAddress = null;
    boundSignerAddress = null;
}

/** Open the public chain cache and ordinary settings without an unlock prompt. */
export async function ensureStorage() {
    await ensureWasmInit();
    if (!storageOpening) {
        storageOpening = (async () => {
            const storage = await Storage.connect();
            installStoragePauseOnUnload(storage);
            storageHandle = storage;
            bindAppStorage(storage);
        })().catch((err) => {
            storageOpening = null;
            throw err;
        });
    }
    await storageOpening;
    return appStorageInstance;
}

/** Ask for access only when the user requests private data or a private operation. */
export async function ensurePrivateStorage() {
    await ensureStorage();
    if (privateUnlocked) return appStorageInstance;
    if (!privateOpening) {
        privateOpening = (async () => {
            await unlockStorage(storageHandle, { onReset: resetLocalData, onOpened: () => {
                // Protect the remaining onboarding steps as soon as the vault opens.
                if (!stopAutoLock) stopAutoLock = startAutoLock(() => void lockStorage());
            } });
            privateUnlocked = true;
            window.dispatchEvent(new Event(STORAGE_UNLOCKED_EVENT));
        })().finally(() => { privateOpening = null; });
    }
    await privateOpening;
    return appStorageInstance;
}

/**
 * Drop private data and keys by closing workers and reloading. The next page
 * opens the public cache without prompting; private access requires an unlock.
 */
export async function lockStorage() {
    privateUnlocked = false;
    stopAutoLock?.();
    stopAutoLock = null;
    disposeClient();
    await closeAndReload(storageHandle);
}

/** Delete local databases without requiring private access or wallet approval. */
export async function resetLocalData() {
    await ensureStorage();
    // Stop the indexer before deletion so it cannot repopulate the empty cache
    // with progress from the old session.
    disposeClient();
    await withStorageActivity(() => storageHandle.reset());
    await lockStorage();
}

/** Settings access to the currently unlocked worker; never opens a dialog. */
export function unlockedStorage() {
    if (!privateUnlocked) throw new Error('Unlock private data first.');
    return storageHandle;
}

/** Whether the local database has been unlocked on this page. */
export function isStorageUnlocked() {
    return privateUnlocked;
}


/**
 * Ask the storage worker to release its OPFS sync access handles as soon as
 * this page starts unloading, instead of waiting for the worker to be torn
 * down by the browser (which happens asynchronously and can race the next
 * page's worker trying to acquire the same handles — surfacing as a false
 * "another tab is using this app" error).
 *
 * Fire-and-forget: we don't await the response, since the page may not
 * survive long enough to receive it. Posting the request is enough — the
 * worker releases the handles synchronously as soon as it processes the
 * message.
 */
function installStoragePauseOnUnload(storage) {
    const pause = () => {
        try {
            storage.call('Pause', 1_000)?.catch(() => {});
        } catch {
            // Best-effort: nothing to do if the worker is already gone.
        }
    };
    const restore = event => { if (event.persisted) window.location.reload(); };
    window.addEventListener('pagehide', pause);
    window.addEventListener('pageshow', restore);
    return () => {
        window.removeEventListener('pagehide', pause);
        window.removeEventListener('pageshow', restore);
    };
}

/**
 * Probe whether the wallet RPC needs a historical-sync bootnode.
 * Opens storage if needed; does not build a Client.
 * @param {string} rpcUrl
 */
export async function bootnodeRequired(rpcUrl) {
    if (!rpcUrl) {
        throw new Error('rpcUrl is required');
    }
    await ensureStorage();
    const contractConfig = await loadDeploymentConfig();
    return sdkBootnodeRequired(rpcUrl, storageHandle, { contractConfig });
}

/**
 * Open storage + client shell for the given Soroban RPC URL.
 * Prefer resolving bootnode (via {@link bootnodeRequired} + settings/modal)
 * before this so the Client is built once with the right URL.
 * @param {string} rpcUrl
 * @param {{ bootnodeUrl?: string|null }} [options]
 */
export async function initializeRuntime(rpcUrl, { bootnodeUrl } = {}) {
    await ensureStorage();

    if (currentRpcUrl !== rpcUrl) {
        disposeClient();
        currentRpcUrl = rpcUrl;
        currentBootnodeUrl = null;
    }

    let resolvedBootnode = bootnodeUrl;
    if (resolvedBootnode === undefined && appStorageInstance) {
        resolvedBootnode = await appStorageInstance.getStoredBootnodeUrl();
    }

    if (
        !wrappedClient ||
        (resolvedBootnode ?? null) !== (currentBootnodeUrl ?? null)
    ) {
        disposeClient();
        currentBootnodeUrl = resolvedBootnode ?? null;
        wrappedClient = await openWrappedClient(
            storageHandle,
            rpcUrl,
            currentBootnodeUrl,
        );
    }

    return client();
}

/**
 * The Soroban RPC URL the current runtime was initialized with, or `null`
 * before {@link initializeRuntime} has run.
 * @returns {string|null}
 */
export function getCurrentRpcUrl() {
    return currentRpcUrl;
}

/**
 * Derive the ASP membership leaf from explicit public inputs (no account session).
 * @param {string} notePublicKey `0x`-prefixed 32-byte hex
 * @param {string} membershipBlinding `0x`-prefixed 32-byte hex field
 * @returns {Promise<string>} leaf as `0x` hex
 */
export async function deriveAspUserLeaf(notePublicKey, membershipBlinding) {
    await ensureWasmInit();
    return sdkDeriveAspUserLeaf(notePublicKey, membershipBlinding);
}

/**
 * Verify a selective-disclosure receipt with no wallet, no local storage, and
 * no prior `initializeRuntime` call — skips the OPFS/SQLite storage worker
 * entirely, since verification never reads local state.
 */
export async function verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash) {
    await ensureWasmInit();
    const contractConfig = await loadDeploymentConfig();
    return sdkVerifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, {
        contractConfig,
        circuitsBaseUrl: circuitsBaseUrl(),
    });
}

/** SDK deployment client + cached account session. */
export function client() {
    if (!wrappedClient) {
        throw new Error('Runtime not initialized. Call initializeRuntime first.');
    }
    return wrappedClient;
}

/** Whether a runtime (wallet-bound or anonymous) is already open. */
export function isRuntimeReady() {
    return wrappedClient !== null;
}

/** Configure telemetry settings in the WASM SDK. */
export async function configureTelemetrySettings(config) {
    await ensureWasmInit();
    configureTelemetry(config);
}

/** Dump recent logs from the WASM SDK ring buffer. */
export async function dumpTelemetryLogs() {
    await ensureWasmInit();
    return dump_recent_logs();
}

/** Whether the WASM build supports debug/trace logging and sensitive reveal. */
export function debugLogsEnabled() {
    return sdkDebugLogsEnabled();
}

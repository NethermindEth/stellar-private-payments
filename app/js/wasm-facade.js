/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, `Account`, and app persistence.
 *
 * Lifecycle: `bootnodeCheck` / `bootnodeRequired` → `initializeRuntime` →
 * `client().backgroundSync` → `client().openAccount` → `account().pool`.
 *
 * Privacy key reads use the SDK (`account().userPublicKeys`, `account().aspSecret`, etc.).
 * App-only persistence (disclaimer, explorer, bootnode, op history, key probe) stays on `storage()`.
 */

import init, {
  Client,
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
import {
    requireNoteOwner,
    sessionMatchesCache,
    createSessionGeneration,
    openPairKey,
    createInFlightOpenRegistry,
} from './account-session-guard.js';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let boundAccount = null;
let wasmReady = false;
let currentRpcUrl = null;
let currentBootnodeUrl = null;
let boundUserAddress = null;
let boundSignerAddress = null;
// Every openAccount that reaches the SDK claims a token. A call whose token
// is no longer current when it returns was superseded while it was in
// flight, and must not write its result over the newer session's.
const openAccountGeneration = createSessionGeneration();
const inFlightOpens = createInFlightOpenRegistry();

export async function ensureWasmInit() {
    if (!wasmReady) {
        await init();
        wasmReady = true;
    }
}

function bindAppStorage(sdkStorage) {
    appStorageInstance = new AppStorage(sdkStorage);
}

function wrapSdkClient(sdk) {
    return {
        ...sdk,
        contractConfig() {
            return Client.contractConfig();
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
        stopBackgroundSync() {
            sdk.stopBackgroundSync();
        },
        /**
         * Revoke the storage worker's session binding. The local database is
         * untouched, so reconnecting restores the session.
         */
        async releaseStorageSession() {
            await sdk.releaseStorageSession();
        },
        async openAccount(
            { networkPassphrase, userAddress, signerAddress },
            signer = new FreighterSigner(),
        ) {
            // Without this the SDK falls back to signer.getPublicKey() and
            // adopts whichever account the wallet has active, and the cache
            // below would be keyed on null.
            requireNoteOwner(userAddress);
            const effectiveSigner = signerAddress ?? userAddress;
            // Keyed on both identities: a session bound to one signing
            // account must never be handed back for another, which a
            // cache keyed on the note owner alone would do silently.
            if (
                boundAccount &&
                sessionMatchesCache(
                    { userAddress: boundUserAddress, signerAddress: boundSignerAddress },
                    { userAddress, signerAddress: effectiveSigner },
                )
            ) {
                return boundAccount;
            }

            // Compared at the point of the cache WRITE, not before the call:
            // an abandoned open can resolve last and overwrite a newer session.
            return inFlightOpens.share(openPairKey(userAddress, effectiveSigner), async () => {
                const generation = openAccountGeneration.begin();
                const account = await sdk.account(
                    {
                        networkPassphrase,
                        userAddress,
                        signerAddress: effectiveSigner,
                    },
                    signer,
                );
                if (!openAccountGeneration.isCurrent(generation)) {
                    const error = new Error(
                        'Account session superseded: another account was opened while this one was still opening.',
                    );
                    error.code = 'SESSION_SUPERSEDED';
                    throw error;
                }
                boundAccount = account;
                boundUserAddress = userAddress;
                boundSignerAddress = effectiveSigner;
                return boundAccount;
            });
        },
        account() {
            if (!boundAccount) {
                throw new Error('Account session not open. Call openAccount() first.');
            }
            return {
                portfolio: () => boundAccount.portfolio(),
                userPublicKeys: () => boundAccount.userPublicKeys(),
                aspSecret: () => boundAccount.aspSecret(),
                userNotes: (limit) => boundAccount.userNotes(limit),
                isRegistered: () => boundAccount.isRegistered(),
                registerPublicKeys: (options) => boundAccount.registerPublicKeys(options ?? {}),
                deriveAspUserLeaf: () => boundAccount.deriveAspUserLeaf(),
                pool: (options) => boundAccount.pool(options),
            };
        },
    };
}

async function openWrappedClient(sdkStorage, rpcUrl, bootnodeUrl) {
    const sdk = await Client.new({
        storage: sdkStorage,
        rpcUrl,
        bootnodeUrl: bootnodeUrl ?? undefined,
    });
    return wrapSdkClient(sdk);
}

/**
 * Stop background sync and drop the in-memory client/account (e.g. disconnect
 * or rebuild).
 *
 * Note what dropping the client does *not* do: the storage worker's session
 * binding lives in the worker isolate, which outlives every Client built
 * against it. Releasing it is `wrappedClient.releaseStorageSession()`, and it
 * is what revokes the worker's capability to serve this account's privacy
 * keys - see the TODO in the body.
 *
 * The release is deliberately not awaited. Awaiting it would close the window
 * between this returning and the worker actually unbinding, but disposeClient
 * is synchronous and called from navigation.js's disconnect() - which the
 * account watcher drives - and twice from initializeRuntime(). Making it async
 * perturbs teardown ordering that the account-rebinding work already tuned, to
 * close a gap that needs a retained Account reference to exploit.
 *
 * Both guards around it are load-bearing: `catch` for a synchronous throw from
 * an already-dropped client, `.catch()` for a rejection arriving after
 * teardown. Either escaping would skip the invalidate() below, which is what
 * stops a superseded open from repopulating the cache.
 */
export function disposeClient() {
    try {
        wrappedClient?.stopBackgroundSync?.();
    } catch {
        // Client may already be tearing down.
    }
    try {
        // Revokes the worker's capability to serve this account's key
        // material, including to retained Account references (see above).
        void wrappedClient?.releaseStorageSession?.()?.catch(() => {});
    } catch {
        // Client may already be tearing down.
    }
    wrappedClient = null;
    boundAccount = null;
    boundUserAddress = null;
    boundSignerAddress = null;
    // A teardown supersedes anything still opening, or that call would
    // repopulate the cache moments after it was cleared.
    openAccountGeneration.invalidate();
    inFlightOpens.clear();
}

/**
 * Open local persistence (and app storage helpers) without building a Client.
 * @returns {Promise<import('./app-storage.js').AppStorage>}
 */
export async function ensureStorage() {
    await ensureWasmInit();
    if (!storageHandle) {
        storageHandle = await Storage.open();
        bindAppStorage(storageHandle);
    }
    return appStorageInstance;
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
    return sdkBootnodeRequired(rpcUrl, storageHandle);
}

/**
 * Open storage + client shell for the given Soroban RPC URL.
 * Prefer resolving bootnode (via {@link bootnodeRequired} + settings/modal)
 * before this so the Client is built once with the right URL.
 * @param {string} rpcUrl
 * @param {{ bootnodeUrl?: string|null }} [options]
 */
export async function initializeRuntime(rpcUrl, { bootnodeUrl, address } = {}) {
    await ensureStorage();

    if (currentRpcUrl !== rpcUrl) {
        disposeClient();
        currentRpcUrl = rpcUrl;
        currentBootnodeUrl = null;
    }

    let resolvedBootnode = bootnodeUrl;
    if (resolvedBootnode === undefined && appStorageInstance) {
        // The stored bootnode is account-scoped. Without an address there
        // is no account whose endpoint this could be, so the fallback yields
        // undefined rather than reaching for whatever was stored globally.
        resolvedBootnode = await appStorageInstance.getStoredBootnodeUrl(address);
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
    return sdkVerifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash);
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

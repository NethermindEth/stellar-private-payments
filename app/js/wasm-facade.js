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
  FreighterSigner,
  Storage,
  bootnodeRequired as sdkBootnodeRequired,
} from 'stellar-private-payments-sdk-web';

import { AppStorage } from './app-storage.js';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let boundAccount = null;
let wasmReady = false;
let currentRpcUrl = null;
let currentBootnodeUrl = null;
let boundUserAddress = null;

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
        async openAccount(
            { networkPassphrase, userAddress },
            signer = new FreighterSigner(),
        ) {
            if (boundUserAddress === userAddress && boundAccount) {
                return boundAccount;
            }

            boundAccount = await sdk.account(
                {
                    networkPassphrase,
                    userAddress,
                },
                signer,
            );
            boundUserAddress = userAddress;
            return boundAccount;
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
                deriveAspUserLeaf: (options) => boundAccount.deriveAspUserLeaf(options),
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

/** Drop the in-memory SDK client and account session (e.g. on wallet disconnect). */
export function resetWalletSession() {
    boundUserAddress = null;
    boundAccount = null;
    wrappedClient = null;
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
export async function initializeRuntime(rpcUrl, { bootnodeUrl } = {}) {
    await ensureStorage();

    if (currentRpcUrl !== rpcUrl) {
        wrappedClient = null;
        boundAccount = null;
        currentRpcUrl = rpcUrl;
        boundUserAddress = null;
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
        currentBootnodeUrl = resolvedBootnode ?? null;
        wrappedClient = await openWrappedClient(
            storageHandle,
            rpcUrl,
            currentBootnodeUrl,
        );
        boundAccount = null;
        boundUserAddress = null;
    }

    return client();
}

/** SDK deployment client + cached account session. */
export function client() {
    if (!wrappedClient) {
        throw new Error('Runtime not initialized. Call initializeRuntime first.');
    }
    return wrappedClient;
}

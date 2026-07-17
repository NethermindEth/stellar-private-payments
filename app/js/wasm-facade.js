/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, `Account`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `client().startSync` → `client().openAccount` → `account().pool`.
 *
 * Privacy key reads use the SDK (`account().userPublicKeys`, `account().aspSecret`, etc.).
 * App-only persistence (disclaimer, explorer, bootnode, op history, key probe) stays on `storage()`.
 */

import init, {
    Client,
    FreighterSigner,
    Storage,
    verifySelectiveDisclosure as sdkVerifySelectiveDisclosure,
} from 'stellar-private-payments-sdk-web';

import { AppStorage } from './app-storage.js';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let boundAccount = null;
let wasmReady = false;
let currentRpcUrl = null;
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
                throw new Error('Runtime not initialized. Call initializeRuntime first.');
            }
            return appStorageInstance;
        },
        async startSync({ bootnodeUrl } = {}) {
            let resolvedBootnode = bootnodeUrl;
            if (resolvedBootnode === undefined) {
                resolvedBootnode = await sdk.checkSync();
            }
            await sdk.startSync({
                bootnodeUrl: resolvedBootnode ?? undefined,
            });
        },
        async openAccount(
            { networkPassphrase, userAddress },
            signer = new FreighterSigner(),
        ) {
            if (boundUserAddress === userAddress && boundAccount) {
                return boundAccount;
            }

            if (boundUserAddress != null) {
                wrappedClient = await openWrappedClient(storageHandle, currentRpcUrl);
                boundAccount = null;
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

async function openWrappedClient(sdkStorage, rpcUrl) {
    const sdk = await Client.new({ storage: sdkStorage, rpcUrl });
    return wrapSdkClient(sdk);
}

/** Drop the in-memory SDK client and account session (e.g. on wallet disconnect). */
export function resetWalletSession() {
    boundUserAddress = null;
    boundAccount = null;
    wrappedClient = null;
}

/** Open storage + client shell for the given Soroban RPC URL. */
export async function initializeRuntime(rpcUrl) {
    await ensureWasmInit();

    if (!storageHandle || currentRpcUrl !== rpcUrl) {
        storageHandle = await Storage.open();
        bindAppStorage(storageHandle);
        wrappedClient = null;
        boundAccount = null;
        currentRpcUrl = rpcUrl;
        boundUserAddress = null;
    }

    if (!wrappedClient) {
        wrappedClient = await openWrappedClient(storageHandle, rpcUrl);
    }

    return client();
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

/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `client().startSync` → `client().initializeWallet` → pool ops.
 */

import init, { Client, FreighterSigner, Storage } from 'stellar-private-payments-sdk-web';

import { AppStorage, storageCall } from './app-storage.js';

const KEY_DERIVATION_MESSAGE = 'Privacy Pool Key Derivation [v1]';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let wasmReady = false;
let syncStarted = false;
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

function wrapSdkClient(sdk, sdkStorage) {
    return {
        ...sdk,
        contractConfig() {
            return Client.contractConfig();
        },
        storage() {
            if (!appStorageInstance) {
                throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
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
            syncStarted = true;
        },
        async initializeWallet(
            { networkPassphrase, userAddress },
            signer = new FreighterSigner(),
        ) {
            if (boundUserAddress === userAddress) return;

            if (boundUserAddress != null) {
                wrappedClient = await openWrappedClient(storageHandle, currentRpcUrl);
            }

            await client().initialize(
                {
                    networkPassphrase,
                    userAddress,
                },
                signer,
            );
            boundUserAddress = userAddress;
        },
        verifySelectiveDisclosure(receiptJson, expectedVkHash) {
            return sdk.verifySelectiveDisclosure(receiptJson, expectedVkHash);
        },
        async getUserKeys(address) {
            const response = await storageCall(sdkStorage, { UserKeys: address });
            return response.UserKeys ?? null;
        },
        async getAspSecret(address) {
            const response = await storageCall(sdkStorage, { AspSecret: address });
            return response.AspSecret ?? null;
        },
        async deriveAndSaveUserKeys(address, signatureBytes, network) {
            await storageCall(
                sdkStorage,
                {
                    DeriveSaveUserKeys: [address, Array.from(signatureBytes), network],
                },
                10_000,
            );
        },
        keyDerivationMessage() {
            return KEY_DERIVATION_MESSAGE;
        },
        async getPortfolioBalances(address) {
            const response = await storageCall(sdkStorage, { PortfolioBalances: address });
            return response.PortfolioBalances ?? [];
        },
        async getOperationalFeed(limit) {
            const config = Client.contractConfig();
            const response = await storageCall(sdkStorage, {
                OperationalFeed: {
                    limit,
                    asp_membership_contract_id: config.asp_membership,
                    public_key_registry_contract_id: config.public_key_registry,
                },
            });
            return response.OperationalFeed ?? [];
        },
        async getUserNotes(address, limit) {
            const response = await storageCall(sdkStorage, { UserNotes: [address, limit] });
            return response.UserNotes ?? [];
        },
        async deriveAspUserLeaf(membershipBlinding, pubkeyHex) {
            const response = await storageCall(sdkStorage, {
                DeriveASPleaf: {
                    membershipBlinding: membershipBlinding.toString(),
                    pubkey: pubkeyHex,
                },
            });
            const leaf = response.DeriveASPleaf;
            if (leaf == null) {
                throw new Error('DeriveASPleaf returned no leaf');
            }
            return typeof leaf === 'string' ? leaf : String(leaf);
        },
        async loadPublicKeys(address) {
            const data = await this.getUserKeys(address);
            if (!data?.noteKeypair?.public) {
                throw new Error('Privacy keys not found in local storage');
            }
            return {
                pubKey: data.noteKeypair.public,
                encryptionKeypair: { publicKey: data.encryptionKeypair.public },
            };
        },
        async aspState() {
            const data = await sdk.aspState();
            return {
                aspMembership: data.aspMembership,
                aspNonMembership: data.aspNonMembership,
            };
        },
    };
}

async function openWrappedClient(sdkStorage, rpcUrl) {
    const sdk = await Client.new({ storage: sdkStorage, rpcUrl });
    return wrapSdkClient(sdk, sdkStorage);
}

/** Drop the in-memory SDK client shell (e.g. on wallet disconnect). Storage worker stays open. */
export function resetWalletSession() {
    boundUserAddress = null;
    wrappedClient = null;
    syncStarted = false;
}

/** Open storage + client shell for the given Soroban RPC URL. */
export async function initializeRuntime(rpcUrl) {
    await ensureWasmInit();

    if (!storageHandle || currentRpcUrl !== rpcUrl) {
        storageHandle = await Storage.open();
        bindAppStorage(storageHandle);
        wrappedClient = null;
        currentRpcUrl = rpcUrl;
        syncStarted = false;
        boundUserAddress = null;
    }

    if (!wrappedClient) {
        wrappedClient = await openWrappedClient(storageHandle, rpcUrl);
    }

    return client();
}

/**
 * Legacy entry for admin/disclosure pages: runtime + event sync, no wallet.
 * Prefer `initializeRuntime` + `client().startSync` in new code.
 */
export async function initializeWasm(rpcUrl, bootnodeUrl = null) {
    if (storageHandle && currentRpcUrl === rpcUrl && syncStarted && bootnodeUrl == null) {
        return client();
    }

    const activeClient = await initializeRuntime(rpcUrl);

    if (bootnodeUrl) {
        await activeClient.startSync({ bootnodeUrl });
    } else if (!syncStarted) {
        await activeClient.startSync();
    }

    return client();
}

/** SDK session + storage-backed reads (keys, notes, feeds, ASP helpers). */
export function client() {
    if (!wrappedClient) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return wrappedClient;
}

/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `client().startEventSync` → `client().initializeWallet` → pool ops.
 */

import init, { Client, FreighterSigner, Storage } from 'stellar-private-payments-sdk-web';

import { PROVER_WORKER_URL, STORAGE_WORKER_URL } from './runtime-paths.js';
import { AppStorage, storageCall } from './app-storage.js';

const KEY_DERIVATION_MESSAGE = 'Privacy Pool Key Derivation [v1]';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let wasmReady = false;
let eventSyncStarted = false;
let currentRpcUrl = null;
let boundUserAddress = null;

export { PROVER_WORKER_URL, STORAGE_WORKER_URL };

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
        async startEventSync({ bootnodeUrl } = {}) {
            let resolvedBootnode = bootnodeUrl;
            if (resolvedBootnode === undefined) {
                resolvedBootnode = await sdk.checkEventSync();
            }
            await sdk.startEventSync({
                bootnodeUrl: resolvedBootnode ?? undefined,
            });
            eventSyncStarted = true;
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
                    proverWorkerUrl: PROVER_WORKER_URL,
                },
                signer,
            );
            boundUserAddress = userAddress;
        },
        verifySelectiveDisclosure(receiptJson, expectedVkHash) {
            return sdk.verifySelectiveDisclosure(receiptJson, expectedVkHash, {
                proverWorkerUrl: PROVER_WORKER_URL,
            });
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
        async getRecentPublicKeys(limit) {
            const response = await storageCall(sdkStorage, { RecentPubKeys: limit });
            return response.PubKeys ?? [];
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
        async loadWalletKeys(address) {
            const data = await this.getUserKeys(address);
            const aspSecret = await this.getAspSecret(address);
            if (!data?.noteKeypair?.public || !aspSecret?.membershipBlinding) {
                throw new Error('Privacy keys not found in local storage');
            }
            return {
                pubKey: data.noteKeypair.public,
                encryptionKeypair: { publicKey: data.encryptionKeypair.public },
                aspSecret: aspSecret.membershipBlinding,
            };
        },
        async aspState() {
            try {
                const data = await this.allContractsData();
                return {
                    aspMembership: data.aspMembership,
                    aspNonMembership: data.aspNonMembership,
                };
            } catch (error) {
                const message = error?.message || '';
                if (!message.includes('initialize')) {
                    throw error;
                }
                throw new Error('ASP state requires an initialized wallet session');
            }
        },
    };
}

async function openWrappedClient(sdkStorage, rpcUrl) {
    const sdk = await Client.new({ storage: sdkStorage, rpcUrl });
    return wrapSdkClient(sdk, sdkStorage);
}

/** Open storage + client shell for the given Soroban RPC URL. */
export async function initializeRuntime(rpcUrl) {
    await ensureWasmInit();

    if (!storageHandle || currentRpcUrl !== rpcUrl) {
        storageHandle = await Storage.open({ workerUrl: STORAGE_WORKER_URL });
        bindAppStorage(storageHandle);
        wrappedClient = await openWrappedClient(storageHandle, rpcUrl);
        currentRpcUrl = rpcUrl;
        eventSyncStarted = false;
        boundUserAddress = null;
    }

    return client();
}

/**
 * Legacy entry for admin/disclosure pages: runtime + event sync, no wallet.
 * Prefer `initializeRuntime` + `client().startEventSync` in new code.
 */
export async function initializeWasm(rpcUrl, bootnodeUrl = null) {
    if (storageHandle && currentRpcUrl === rpcUrl && eventSyncStarted && bootnodeUrl == null) {
        return client();
    }

    const activeClient = await initializeRuntime(rpcUrl);

    if (bootnodeUrl) {
        await activeClient.startEventSync({ bootnodeUrl });
    } else if (!eventSyncStarted) {
        await activeClient.startEventSync();
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

/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `startEventSync` → `initializeWallet` → pool ops.
 */

import init, { Client, FreighterSigner, Storage } from 'stellar-private-payments-sdk-web';

import { PROVER_WORKER_URL, STORAGE_WORKER_URL } from './runtime-paths.js';
import { AppStorage, storageCall } from './app-storage.js';

const KEY_DERIVATION_MESSAGE = 'Privacy Pool Key Derivation [v1]';

let storage = null;
let appStorageInstance = null;
let wrappedClient = null;
let wasmReady = false;
let eventSyncStarted = false;
let currentRpcUrl = null;
let boundUserAddress = null;

export { PROVER_WORKER_URL, STORAGE_WORKER_URL };

export function contractConfig() {
    return Client.contractConfig();
}

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
    const cfg = contractConfig;
    return {
        ...sdk,
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
            const config = cfg();
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

    if (!storage || currentRpcUrl !== rpcUrl) {
        storage = await Storage.open({ workerUrl: STORAGE_WORKER_URL });
        bindAppStorage(storage);
        wrappedClient = await openWrappedClient(storage, rpcUrl);
        currentRpcUrl = rpcUrl;
        eventSyncStarted = false;
        boundUserAddress = null;
    }

    return { storage: appStorage(), client: client() };
}

/**
 * Probe RPC retention and start background event sync.
 * Throws when the RPC has a sync gap and no bootnode URL is available.
 */
export async function startEventSync({ bootnodeUrl } = {}) {
    const activeClient = client();

    let resolvedBootnode = bootnodeUrl;
    if (resolvedBootnode === undefined) {
        resolvedBootnode = await activeClient.checkEventSync();
    }

    await activeClient.startEventSync({
        bootnodeUrl: resolvedBootnode ?? undefined,
    });
    eventSyncStarted = true;
}

/** Bind wallet signer, spawn workers, derive privacy keys when missing. Idempotent per address. */
export async function initializeWallet(
    { networkPassphrase, userAddress },
    signer = new FreighterSigner(),
) {
    if (boundUserAddress === userAddress) return;

    if (boundUserAddress != null) {
        wrappedClient = await openWrappedClient(storage, currentRpcUrl);
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
}

/**
 * Legacy entry for admin/disclosure pages: runtime + event sync, no wallet.
 * Prefer `initializeRuntime` + `startEventSync` in new code.
 */
export async function initializeWasm(rpcUrl, bootnodeUrl = null) {
    if (storage && currentRpcUrl === rpcUrl && eventSyncStarted && bootnodeUrl == null) {
        return { storage: appStorage(), client: client() };
    }

    await initializeRuntime(rpcUrl);

    if (bootnodeUrl) {
        await client().startEventSync({ bootnodeUrl });
        eventSyncStarted = true;
    } else if (!eventSyncStarted) {
        await startEventSync();
    }

    return { storage: appStorage(), client: client() };
}

/** SDK storage worker handle (for low-level use). */
export function getStorage() {
    if (!storage) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return storage;
}

/** App persistence: settings, disclaimer, operation history. */
export function appStorage() {
    if (!appStorageInstance) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return appStorageInstance;
}

/** SDK session + storage-backed reads (keys, notes, feeds, ASP helpers). */
export function client() {
    if (!wrappedClient) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return wrappedClient;
}

// --- Client (requires `initializeWallet` for chain + pool ops) ---

export async function allContractsData() {
    return client().allContractsData();
}

export async function lookupRegisteredPublicKey(address) {
    return client().lookupRegisteredPublicKey(address);
}

export async function registerPublicKeys(options) {
    return client().registerPublicKeys(options);
}

export async function openPool({ poolContract }) {
    return client().pool({ poolContract });
}

export async function verifySelectiveDisclosure(receiptJson, expectedVkHash) {
    return client().verifySelectiveDisclosure(receiptJson, expectedVkHash, {
        proverWorkerUrl: PROVER_WORKER_URL,
    });
}

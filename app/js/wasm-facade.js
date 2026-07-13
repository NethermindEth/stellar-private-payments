/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, `Account`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `client().startSync` → `client().openAccount` → `account().pool`.
 */

import init, { Client, FreighterSigner, Storage } from 'stellar-private-payments-sdk-web';

import { AppStorage, storageCall } from './app-storage.js';

const KEY_DERIVATION_MESSAGE = 'Privacy Pool Key Derivation [v1]';

let storageHandle = null;
let appStorageInstance = null;
let wrappedClient = null;
let boundAccount = null;
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

function toScalarHex(value) {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    return `0x${n.toString(16).padStart(64, '0')}`;
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
            return boundAccount;
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
        async deriveAspUserLeaf(membershipBlinding, notePublicKey) {
            const response = await storageCall(sdkStorage, {
                DeriveASPleaf: {
                    membershipBlinding: toScalarHex(membershipBlinding),
                    pubkey: toScalarHex(notePublicKey),
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

/** Drop the in-memory SDK client and account session (e.g. on wallet disconnect). */
export function resetWalletSession() {
    boundUserAddress = null;
    boundAccount = null;
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
        boundAccount = null;
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

/** SDK deployment client + cached account session + storage-backed reads. */
export function client() {
    if (!wrappedClient) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return wrappedClient;
}

/** @deprecated Use {@link client}().openAccount */
export async function openAccount(options, signer) {
    return client().openAccount(options, signer);
}

/** @deprecated Use {@link client}().openAccount */
export async function initializeWallet(options, signer) {
    return client().openAccount(options, signer);
}

/**
 * Browser runtime facade — single entry for SDK `Storage`, `Client`, and app persistence.
 *
 * Lifecycle: `initializeRuntime` → `startEventSync` → `initializeWallet` → pool ops.
 */

import init, { Client, FreighterSigner, Storage } from 'stellar-private-payments-sdk';

import { PROVER_WORKER_URL, STORAGE_WORKER_URL } from './runtime-paths.js';
import * as storageApp from './storage-app.js';

let storage = null;
let client = null;
let wasmReady = false;
let eventSyncStarted = false;
let currentRpcUrl = null;
let walletInitialized = false;

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

/** Open storage + client shell for the given Soroban RPC URL. */
export async function initializeRuntime(rpcUrl) {
    await ensureWasmInit();

    if (!storage || currentRpcUrl !== rpcUrl) {
        storage = await Storage.open({ workerUrl: STORAGE_WORKER_URL });
        client = await Client.new({ storage, rpcUrl });
        currentRpcUrl = rpcUrl;
        eventSyncStarted = false;
    }

    return { storage, client };
}

/**
 * Probe RPC retention and start background event sync.
 * Throws when the RPC has a sync gap and no bootnode URL is available.
 */
export async function startEventSync({ bootnodeUrl } = {}) {
    const activeClient = getClient();

    let resolvedBootnode = bootnodeUrl;
    if (resolvedBootnode === undefined) {
        resolvedBootnode = await activeClient.checkEventSync();
    }

    await activeClient.startEventSync({
        bootnodeUrl: resolvedBootnode ?? undefined,
    });
    eventSyncStarted = true;
}

/** Bind wallet signer, spawn workers, derive privacy keys when missing. Idempotent. */
export async function initializeWallet(
    { networkPassphrase, userAddress },
    signer = new FreighterSigner(),
) {
    if (walletInitialized) return;

    await getClient().initialize(
        {
            networkPassphrase,
            userAddress,
            proverWorkerUrl: PROVER_WORKER_URL,
        },
        signer,
    );
    walletInitialized = true;
}

/**
 * Drop the wallet session shell so a later connect can call `initializeWallet` again.
 * Keeps the storage worker and event sync running.
 */
export async function resetWalletSession() {
    if (!storage || !currentRpcUrl) return;
    client = await Client.new({ storage, rpcUrl: currentRpcUrl });
    walletInitialized = false;
}

/**
 * Legacy entry for admin/disclosure pages: runtime + event sync, no wallet.
 * Prefer `initializeRuntime` + `startEventSync` in new code.
 */
export async function initializeWasm(rpcUrl, bootnodeUrl = null) {
    if (storage && currentRpcUrl === rpcUrl && eventSyncStarted && bootnodeUrl == null) {
        return { storage: getStorage(), client: getClient() };
    }

    await initializeRuntime(rpcUrl);

    if (bootnodeUrl) {
        await getClient().startEventSync({ bootnodeUrl });
        eventSyncStarted = true;
    } else if (!eventSyncStarted) {
        await startEventSync();
    }

    return { storage: getStorage(), client: getClient() };
}

export function getStorage() {
    if (!storage) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return storage;
}

export function getClient() {
    if (!client) {
        throw new Error('Runtime not initialized. Call initializeRuntime or initializeWasm first.');
    }
    return client;
}

// --- Client (requires `initializeWallet` for chain + pool ops) ---

export async function allContractsData() {
    return getClient().allContractsData();
}

export async function lookupRegisteredPublicKey(address) {
    return getClient().lookupRegisteredPublicKey(address);
}

export async function registerPublicKeys(options) {
    return getClient().registerPublicKeys(options);
}

export async function openPool({ poolContract }) {
    return getClient().pool({ poolContract });
}

/** ASP membership/non-membership snapshot (admin, on-chain state). */
export async function aspState() {
    try {
        const data = await allContractsData();
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
}

// --- App persistence (storage worker protocol) ---

export async function getSetting(key) {
    return storageApp.getSetting(getStorage(), key);
}

export async function setSetting(key, value) {
    return storageApp.setSetting(getStorage(), key, value);
}

export async function getExplorerSetting() {
    return storageApp.getExplorerSetting(getStorage());
}

export async function getBootnodeConfig() {
    return storageApp.getBootnodeConfig(getStorage());
}

export async function setBootnodeConfig(url) {
    return storageApp.setBootnodeConfig(getStorage(), url);
}

export async function getDisclaimerState(address) {
    return storageApp.getDisclaimerState(getStorage(), address);
}

export async function acceptDisclaimer(address, disclaimerHashHex) {
    return storageApp.acceptDisclaimer(getStorage(), address, disclaimerHashHex);
}

export async function getUserKeys(address) {
    return storageApp.getUserKeys(getStorage(), address);
}

export async function getAspSecret(address) {
    return storageApp.getAspSecret(getStorage(), address);
}

export async function getPortfolioBalances(address) {
    return storageApp.getPortfolioBalances(getStorage(), address);
}

export async function getOperationalFeed(limit) {
    return storageApp.getOperationalFeed(getStorage(), limit, contractConfig());
}

export async function getUserNotes(address, limit) {
    return storageApp.getUserNotes(getStorage(), address, limit);
}

export async function getRecentPublicKeys(limit) {
    return storageApp.getRecentPublicKeys(getStorage(), limit);
}

export async function recordOperation(fields) {
    return storageApp.recordOperation(getStorage(), fields);
}

export async function listOperations(address, poolContractId, limit) {
    return storageApp.listOperations(getStorage(), address, poolContractId, limit);
}

export async function deriveAspUserLeaf(membershipBlinding, pubkeyHex) {
    return storageApp.deriveAspUserLeaf(getStorage(), membershipBlinding, pubkeyHex);
}

export async function loadWalletKeys(address) {
    const data = await getUserKeys(address);
    const aspSecret = await getAspSecret(address);
    if (!data?.noteKeypair?.public || !aspSecret?.membershipBlinding) {
        throw new Error('Privacy keys not found in local storage');
    }
    return {
        pubKey: data.noteKeypair.public,
        encryptionKeypair: { publicKey: data.encryptionKeypair.public },
        aspSecret: aspSecret.membershipBlinding,
    };
}

export async function getStoredBootnodeUrl() {
    const config = await getBootnodeConfig();
    if (config?.enabled && config.url) {
        return config.url;
    }
    return undefined;
}

export async function verifySelectiveDisclosure(receiptJson, expectedVkHash) {
    return getClient().verifySelectiveDisclosure(receiptJson, expectedVkHash, {
        proverWorkerUrl: PROVER_WORKER_URL,
    });
}


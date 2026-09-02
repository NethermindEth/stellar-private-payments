/**
 * App pool session — SDK `PrivatePool` handle for deposits, transfers, and withdrawals.
 * @module ui/pool
 */

import { client, isRuntimeReady } from '../wasm-facade.js';
import { App } from './core.js';

App.events.addEventListener('pool:selected', () => {
    if (App.state.wallet.connected) {
        createAppPool().catch(err => console.warn('[pool] recreate failed:', err));
    }
});

let cachedContractConfig = null;
let activeSession = null;
let activeSessionContractId = null;
// Concurrent callers (pool.js's own pool:selected listener and any consumer
// calling ensureAppPool during the recreate window) must share a single
// in-flight createAppPool — otherwise closeAppPool inside the second call
// wipes the first call's just-published session.
let pendingSession = null;

export async function getContractConfig() {
    if (cachedContractConfig) return cachedContractConfig;
    cachedContractConfig = client().contractConfig();
    return cachedContractConfig;
}

export function getActivePoolContractId(config = null) {
    const pools = Array.isArray(config?.pools) ? config.pools : (App.state.pools || []);
    const selected = pools.find(p => p?.poolContractId === App.state.selectedPoolId)
        || pools.find(p => p?.enabled)
        || pools[0];
    return selected?.poolContractId || App.state.selectedPoolId || null;
}

export function closeAppPool() {
    activeSession = null;
    activeSessionContractId = null;
}

export async function createAppPool() {
    if (pendingSession) return pendingSession;
    pendingSession = (async () => {
        if (!App.state.wallet.connected || !App.state.wallet.address) {
            throw new Error('Wallet not connected');
        }
        if (!App.state.wallet.networkPassphrase) {
            throw new Error('Wallet network passphrase unavailable');
        }
        // wallet.connected flips true before the runtime finishes initializing
        if (!isRuntimeReady()) {
            throw new Error('Still connecting to your wallet. Please wait a moment and try again.');
        }

        closeAppPool();

        const config = await getContractConfig();
        const poolContract = getActivePoolContractId(config);
        if (!poolContract) throw new Error('Pool contract ID not available');
        await client().openAccount(
            { networkPassphrase: App.state.wallet.networkPassphrase, userAddress: App.state.wallet.address },
        );
        const pool = await client().account().pool({ poolContract });
        activeSession = pool;
        activeSessionContractId = poolContract;
        App.events.dispatchEvent(new CustomEvent('pool:session-ready', { detail: { poolContract } }));
        return pool;
    })().finally(() => {
        pendingSession = null;
    });
    return pendingSession;
}

export async function ensureAppPool() {
    const poolContract = getActivePoolContractId();
    if (!poolContract) throw new Error('Pool contract ID not available');
    if (activeSession && activeSessionContractId === poolContract) return activeSession;
    return createAppPool();
}

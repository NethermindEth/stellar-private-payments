/**
 * App pool session — SDK `PrivatePool` handle for deposits, transfers, and withdrawals.
 * @module ui/pool
 */

import { client } from '../wasm-facade.js';
import { App } from './core.js';

App.events.addEventListener('pool:selected', () => {
    if (App.state.wallet.connected) {
        createAppPool().catch(err => console.warn('[pool] recreate failed:', err));
    }
});

let cachedContractConfig = null;
let activeSession = null;
let activeSessionContractId = null;

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
    if (!App.state.wallet.connected || !App.state.wallet.address) {
        throw new Error('Wallet not connected');
    }
    if (!App.state.wallet.networkPassphrase) {
        throw new Error('Wallet network passphrase unavailable');
    }

    closeAppPool();

    const config = await getContractConfig();
    const poolContract = getActivePoolContractId(config);
    if (!poolContract) throw new Error('Pool contract ID not available');
    const pool = await client().pool({ poolContract });
    activeSession = pool;
    activeSessionContractId = poolContract;
    return pool;
}

export async function ensureAppPool() {
    const poolContract = getActivePoolContractId();
    if (!poolContract) throw new Error('Pool contract ID not available');
    if (activeSession && activeSessionContractId === poolContract) return activeSession;
    return createAppPool();
}

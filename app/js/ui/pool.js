/**
 * App pool session — `createPool` handle for deposits, transfers, and withdrawals.
 * @module ui/pool
 */

import { getHandle } from '../wasm-facade.js';
import { App } from './core.js';

let cachedContractConfig = null;

export async function getContractConfig() {
    if (cachedContractConfig) return cachedContractConfig;
    cachedContractConfig = await getHandle().webClient.contractConfig();
    return cachedContractConfig;
}

export function getActivePoolContractId(config) {
    const pools = Array.isArray(config?.pools) ? config.pools : [];
    const selected = pools.find(p => p?.enabled) || pools[0];
    const poolContractId = selected?.poolContractId;
    if (!poolContractId) throw new Error('Pool contract ID not available');
    return poolContractId;
}

export function closeAppPool() {
    if (App.state.pool) {
        App.state.pool.close();
        App.state.pool = null;
    }
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
    const pool = await getHandle().webClient.createPool({
        poolContract,
        networkPassphrase: App.state.wallet.networkPassphrase,
        userAddress: App.state.wallet.address,
    });
    await pool.initialize();
    App.state.pool = pool;
    return pool;
}

export async function ensureAppPool() {
    if (App.state.pool) return App.state.pool;
    return createAppPool();
}

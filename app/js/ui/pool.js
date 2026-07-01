/**
 * App pool session — `openPool` handle for deposits, transfers, and withdrawals.
 * @module ui/pool
 */

import { contractConfig, openPool } from '../wasm-facade.js';
import { wrapSdkPool } from '../pool-adapter.js';
import { App } from './core.js';

App.events.addEventListener('pool:selected', () => {
    if (App.state.wallet.connected) {
        createAppPool().catch(err => console.warn('[pool] recreate failed:', err));
    }
});

let cachedContractConfig = null;

export async function getContractConfig() {
    if (cachedContractConfig) return cachedContractConfig;
    cachedContractConfig = contractConfig();
    return cachedContractConfig;
}

export function getActivePoolContractId(config) {
    const pools = Array.isArray(config?.pools) ? config.pools : [];
    const selected = pools.find(p => p?.poolContractId === App.state.selectedPoolId)
        || pools.find(p => p?.enabled)
        || pools[0];
    const poolContractId = selected?.poolContractId;
    if (!poolContractId) throw new Error('Pool contract ID not available');
    return poolContractId;
}

export function closeAppPool() {
    App.state.pool = null;
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
    const sdkPool = await openPool({ poolContract });
    const pool = wrapSdkPool(sdkPool, {
        poolContractId: poolContract,
        userAddress: App.state.wallet.address,
    });
    App.state.pool = pool;
    return pool;
}

export async function ensureAppPool() {
    if (App.state.pool) return App.state.pool;
    return createAppPool();
}

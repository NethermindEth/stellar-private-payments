/**
 * RPC retention window detection.
 * Detects whether the connected Soroban RPC has 24h or 7-day event retention.
 *
 * Cache read/write is delegated to the Rust WASM StateManager.
 * RPC probing stays in JS (uses Stellar SDK).
 *
 * @module state/retention-verifier
 */

import { getSorobanServer, getNetwork, getDeployedContracts } from '../stellar.js';
import { get as wasm } from './wasm.js';

const LEDGER_RATE_SECONDS = 5;
const LEDGERS_24H = 17280;   // ~24 hours (24 * 60 * 60 / 5)
const LEDGERS_7D = 120960;   // ~7 days (7 * 24 * 60 * 60 / 5)
const RETENTION_PROBE_SPAN = 32;

/**
 * @typedef {Object} RetentionConfig
 * @property {number} window - Detected retention window in ledgers
 * @property {string} description - Human-readable description
 * @property {number} warningThreshold - Ledgers before warning (80% of window)
 * @property {string} detectedAt - ISO timestamp of detection
 * @property {string} rpcEndpoint - RPC URL used for detection
 */

/**
 * Probes the RPC to detect the actual event retention window.
 * @returns {Promise<RetentionConfig>}
 */
export async function detectRetentionWindow() {
    const server = getSorobanServer();
    const network = getNetwork();
    const rpcEndpoint = network.rpcUrl;

    let latestLedger;
    try {
        const ledgerInfo = await server.getLatestLedger();
        latestLedger = ledgerInfo.sequence;
    } catch (e) {
        console.error('[Retention] Failed to get latest ledger:', e);
        return createFallbackConfig(rpcEndpoint);
    }

    // Try 7 days
    const sevenDaysAgo = Math.max(1, latestLedger - LEDGERS_7D + 1);
    if (await canFetchEventsFrom(server, sevenDaysAgo)) {
        console.log('[Retention] Detected 7-day retention window');
        return {
            window: LEDGERS_7D,
            description: '7 days',
            warningThreshold: Math.floor(LEDGERS_7D * 0.8),
            detectedAt: new Date().toISOString(),
            rpcEndpoint,
        };
    }

    // Try 24 hours
    const oneDayAgo = Math.max(1, latestLedger - LEDGERS_24H + 1);
    if (await canFetchEventsFrom(server, oneDayAgo)) {
        console.log('[Retention] Detected 24-hour retention window');
        return {
            window: LEDGERS_24H,
            description: '24 hours',
            warningThreshold: Math.floor(LEDGERS_24H * 0.8),
            detectedAt: new Date().toISOString(),
            rpcEndpoint,
        };
    }

    console.warn('[Retention] Could not detect retention window, assuming 24 hours');
    return createFallbackConfig(rpcEndpoint);
}

/**
 * Tests if events can be fetched from a given start ledger.
 * @param {import('@stellar/stellar-sdk').rpc.Server} server
 * @param {number} startLedger
 * @returns {Promise<boolean>}
 */
async function canFetchEventsFrom(server, startLedger) {
    try {
        const endLedger = startLedger + RETENTION_PROBE_SPAN;
        const contracts = getDeployedContracts();
        const contractId = contracts?.pool || contracts?.aspMembership || contracts?.aspNonMembership;
        const filters = contractId
            ? [{ type: 'contract', contractIds: [contractId], topics: [['**']] }]
            : [];

        await server.getEvents({
            startLedger,
            endLedger,
            filters,
            limit: 1,
        });
        return true;
    } catch (e) {
        const errorMsg = e.message || String(e);
        if (errorMsg.includes('start is before oldest ledger') ||
            errorMsg.includes('start ledger') ||
            errorMsg.includes('out of range')) {
            return false;
        }
        console.warn('[Retention] Event fetch error:', errorMsg);
        return false;
    }
}

/**
 * Creates a fallback config when detection fails.
 * @param {string} rpcEndpoint
 * @returns {RetentionConfig}
 */
function createFallbackConfig(rpcEndpoint) {
    return {
        window: LEDGERS_24H,
        description: '24 hours (assumed)',
        warningThreshold: Math.floor(LEDGERS_24H * 0.5),
        detectedAt: new Date().toISOString(),
        rpcEndpoint,
    };
}

/**
 * Gets the cached retention config from WASM storage.
 * @param {string} rpcEndpoint
 * @returns {Promise<RetentionConfig|null>}
 */
export async function getCachedRetentionConfig(rpcEndpoint) {
    try {
        return JSON.parse(wasm().get_retention_config(rpcEndpoint));
    } catch (e) {
        console.error('[Retention] Failed to get cached config:', e);
        return null;
    }
}

/**
 * Saves retention config to WASM storage.
 * @param {RetentionConfig} config
 * @returns {Promise<void>}
 */
export async function saveRetentionConfig(config) {
    try {
        wasm().put_retention_config(JSON.stringify(config));
    } catch (e) {
        console.error('[Retention] Failed to save config:', e);
    }
}

/**
 * Gets or detects the retention config for the current RPC.
 * Uses cached value if available and fresh (less than 1 hour old).
 * @param {boolean} forceRefresh
 * @returns {Promise<RetentionConfig>}
 */
export async function getRetentionConfig(forceRefresh = false) {
    const network = getNetwork();
    const rpcEndpoint = network.rpcUrl;

    if (!forceRefresh) {
        const cached = await getCachedRetentionConfig(rpcEndpoint);
        if (cached) {
            const age = Date.now() - new Date(cached.detectedAt).getTime();
            const oneHour = 60 * 60 * 1000;
            if (age < oneHour) {
                console.log('[Retention] Using cached config:', cached.description);
                return cached;
            }
        }
    }

    const config = await detectRetentionWindow();
    await saveRetentionConfig(config);
    return config;
}

/**
 * Converts ledger count to human-readable duration.
 * @param {number} ledgers
 * @returns {string}
 */
export function ledgersToDuration(ledgers) {
    const seconds = ledgers * LEDGER_RATE_SECONDS;
    const hours = Math.floor(seconds / 3600);
    const days = Math.floor(hours / 24);

    if (days > 0) {
        const remainingHours = hours % 24;
        return remainingHours > 0
            ? `${days}d ${remainingHours}h`
            : `${days}d`;
    }
    if (hours > 0) {
        const minutes = Math.floor((seconds % 3600) / 60);
        return minutes > 0
            ? `${hours}h ${minutes}m`
            : `${hours}h`;
    }
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m`;
}

export { LEDGERS_24H, LEDGERS_7D, LEDGER_RATE_SECONDS };

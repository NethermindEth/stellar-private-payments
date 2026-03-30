/**
 * Sync Controller - orchestrates event synchronization for Pool and ASP Membership.
 *
 * Handles:
 * - Incremental sync of contract events
 * - Gap detection
 * - Progress reporting
 * - Note discovery
 *
 * Sync metadata is stored via the Rust WASM StateManager.
 * Event fetching from Stellar RPC stays in JS.
 *
 * @module state/sync-controller
 */

import { get as wasm } from './wasm.js';
import * as poolStore from './pool-store.js';
import * as aspMembershipStore from './asp-membership-store.js';
import * as publicKeyStore from './public-key-store.js';
import * as noteScanner from './note-scanner.js';
import * as notesStore from './notes-store.js';
import { getRetentionConfig, ledgersToDuration } from './retention-verifier.js';
import { fetchAllPoolEvents, fetchAllASPMembershipEvents, getLatestLedger, getNetwork } from '../stellar.js';

/**
 * @typedef {Object} SyncStatus
 * @property {'idle'|'syncing'|'complete'|'broken'|'error'} status
 * @property {string} [message]
 * @property {number} poolLeavesCount
 * @property {number} aspMembershipLeavesCount
 * @property {number} lastSyncedLedger
 * @property {number} latestLedger
 * @property {number} gap
 * @property {boolean} syncBroken
 */

/**
 * @typedef {Object} SyncMetadata
 * @property {string} network
 * @property {Object} poolSync
 * @property {number} poolSync.lastLedger
 * @property {string|null} poolSync.lastCursor
 * @property {boolean} poolSync.syncBroken
 * @property {Object} aspMembershipSync
 * @property {number} aspMembershipSync.lastLedger
 * @property {string|null} aspMembershipSync.lastCursor
 * @property {boolean} aspMembershipSync.syncBroken
 * @property {string} lastSuccessfulSync
 */

let isSyncing = false;
let syncListeners = [];

/**
 * Gets the current sync metadata from WASM storage.
 * @returns {Promise<SyncMetadata|null>}
 */
export async function getSyncMetadata() {
    const network = getNetwork().name;
    return JSON.parse(wasm().get_sync_metadata(network));
}

/**
 * Saves sync metadata via WASM.
 * @param {SyncMetadata} metadata
 * @returns {Promise<void>}
 */
async function saveSyncMetadata(metadata) {
    wasm().put_sync_metadata(JSON.stringify(metadata));
}

/**
 * Creates default sync metadata for a fresh start.
 * @returns {SyncMetadata}
 */
function createDefaultMetadata() {
    return {
        network: getNetwork().name,
        poolSync: {
            lastLedger: 0,
            lastCursor: null,
            syncBroken: false,
        },
        aspMembershipSync: {
            lastLedger: 0,
            lastCursor: null,
            syncBroken: false,
        },
        lastSuccessfulSync: null,
    };
}

/**
 * Checks the sync gap against the retention window.
 * @returns {Promise<{status: 'ok'|'warning'|'broken', message: string, gap: number}>}
 */
export async function checkSyncGap() {
    const metadata = await getSyncMetadata();
    const retentionConfig = await getRetentionConfig();
    const latestLedger = await getLatestLedger();

    const lastSyncedLedger = Math.max(
        metadata?.poolSync?.lastLedger || 0,
        metadata?.aspMembershipSync?.lastLedger || 0
    );

    const gap = latestLedger - lastSyncedLedger;

    if (lastSyncedLedger === 0) {
        return {
            status: 'ok',
            message: 'First sync - starting from scratch',
            gap,
        };
    }

    if (gap > retentionConfig.window) {
        return {
            status: 'broken',
            message: `Offline for more than ${retentionConfig.description}. ` +
                     `Some notes may be inaccessible. Last sync: ${ledgersToDuration(gap)} ago.`,
            gap,
        };
    }

    if (gap > retentionConfig.warningThreshold) {
        const remaining = retentionConfig.window - gap;
        return {
            status: 'warning',
            message: `Last sync was ${ledgersToDuration(gap)} ago. ` +
                     `Sync within ${ledgersToDuration(remaining)} to avoid data loss.`,
            gap,
        };
    }

    return {
        status: 'ok',
        message: `Last sync: ${ledgersToDuration(gap)} ago`,
        gap,
    };
}

/**
 * Starts a full synchronization of Pool and ASP Membership events.
 * @param {Object} [options]
 * @param {function} [options.onProgress] - Progress callback
 * @param {boolean} [options.scanNotes=true] - Scan for new notes
 * @param {boolean} [options.checkSpent=true] - Check spent status
 * @param {boolean} [options.forceRefresh=false] - Ignore cached cursor
 * @returns {Promise<SyncStatus>}
 */
export async function startSync(options = {}) {
    if (isSyncing) {
        return { status: 'syncing', message: 'Sync already in progress' };
    }

    isSyncing = true;
    const { onProgress, scanNotes = true, checkSpent = true, forceRefresh = false } = options;

    try {
        let metadata = await getSyncMetadata() || createDefaultMetadata();
        const latestLedger = await getLatestLedger();
        const retentionConfig = await getRetentionConfig(forceRefresh);

        // Check for sync gap
        const gapCheck = await checkSyncGap();
        if (gapCheck.status === 'broken') {
            metadata.poolSync.syncBroken = true;
            metadata.aspMembershipSync.syncBroken = true;
            await saveSyncMetadata(metadata);
            emit('syncBroken', gapCheck);
            return {
                status: 'broken',
                message: gapCheck.message,
                syncBroken: true,
                gap: gapCheck.gap,
                lastSyncedLedger: Math.max(
                    metadata.poolSync.lastLedger,
                    metadata.aspMembershipSync.lastLedger
                ),
                latestLedger,
                poolLeavesCount: await poolStore.getLeafCount(),
                aspMembershipLeavesCount: await aspMembershipStore.getLeafCount(),
            };
        }

        const retentionStartLedger = Math.max(1, latestLedger - retentionConfig.window + 1);
        const poolStartLedger = retentionStartLedger;
        const aspStartLedger = retentionStartLedger;

        emit('syncProgress', { phase: 'pool', progress: 0 });

        // Sync Pool events
        let poolEventCount = 0;
        let publicKeyCount = 0;
        const poolCursor = forceRefresh ? null : metadata.poolSync.lastCursor;
        const poolResult = await fetchAllPoolEvents({
            startLedger: poolStartLedger,
            endLedger: latestLedger,
            cursor: poolCursor,
            onPage: async (events, cursor) => {
                await poolStore.processEvents(events);
                const pkResult = await publicKeyStore.processEvents(events);
                publicKeyCount += pkResult.registrations;
                poolEventCount += events.length;
                if (onProgress) {
                    onProgress({ phase: 'pool', events: events.length, cursor });
                }
            },
        });

        if (poolResult.success) {
            metadata.poolSync.lastLedger = poolResult.latestLedger;
            metadata.poolSync.lastCursor = poolResult.cursor;
            metadata.poolSync.syncBroken = false;

            await poolStore.rebuildTree();
        }

        emit('syncProgress', { phase: 'asp_membership', progress: 50 });

        // Sync ASP Membership events
        let aspEventCount = 0;
        let aspLeafAddedCount = 0;
        const aspCursor = forceRefresh ? null : metadata.aspMembershipSync.lastCursor;

        console.log('[SyncController] Starting ASP Membership sync:', {
            startLedger: aspStartLedger,
            latestLedger,
            hasCursor: !!aspCursor,
            cursor: aspCursor ? aspCursor.slice(0, 20) + '...' : null,
            retentionWindow: retentionConfig.window,
        });

        const aspResult = await fetchAllASPMembershipEvents({
            startLedger: aspStartLedger,
            endLedger: latestLedger,
            cursor: aspCursor,
            onPage: async (events, cursor) => {
                const leafEvents = await aspMembershipStore.processEvents(events);
                aspEventCount += events.length;
                aspLeafAddedCount += leafEvents;
                if (onProgress) {
                    onProgress({ phase: 'asp_membership', events: events.length, cursor });
                }
            },
        });

        console.log('[SyncController] ASP Membership sync complete:', {
            totalEvents: aspEventCount,
            leafAddedEvents: aspLeafAddedCount,
            success: aspResult.success,
        });

        if (aspResult.success) {
            metadata.aspMembershipSync.lastLedger = aspResult.latestLedger;
            metadata.aspMembershipSync.lastCursor = aspResult.cursor;
            metadata.aspMembershipSync.syncBroken = false;

            const localLeafCount = await aspMembershipStore.getLeafCount();
            const { readASPMembershipState } = await import('../stellar.js');
            const onChainState = await readASPMembershipState();

            if (onChainState.success) {
                const onChainLeafCount = onChainState.nextIndex || 0;
                if (localLeafCount < onChainLeafCount) {
                    console.warn('[SyncController] ASP Membership sync incomplete:');
                    console.warn(`  On-chain has ${onChainLeafCount} leaves, local has ${localLeafCount}`);
                    console.warn('  Some events may be outside RPC retention window (24h-7d)');
                    metadata.aspMembershipSync.syncBroken = true;
                } else {
                    console.log(`[SyncController] ASP Membership in sync: ${localLeafCount}/${onChainLeafCount} leaves`);
                }
            }
        }

        // Update metadata
        metadata.lastSuccessfulSync = new Date().toISOString();
        await saveSyncMetadata(metadata);

        // Note scanning
        let scanResult = null;
        let spentResult = null;
        const hasKeys = notesStore.hasAuthenticatedKeys();

        if (hasKeys && scanNotes) {
            emit('syncProgress', { phase: 'note_scanning', progress: 75 });

            scanResult = await noteScanner.scanForNotes({
                onProgress: (scanned, total) => {
                    if (onProgress) {
                        onProgress({ phase: 'note_scanning', scanned, total });
                    }
                },
            });

            if (scanResult.found > 0) {
                emit('notesDiscovered', {
                    found: scanResult.found,
                    notes: scanResult.notes,
                });
            }
        }

        if (hasKeys && checkSpent) {
            emit('syncProgress', { phase: 'checking_spent', progress: 90 });

            spentResult = await noteScanner.checkSpentNotes();

            if (spentResult.markedSpent > 0) {
                emit('notesMarkedSpent', {
                    count: spentResult.markedSpent,
                });
            }
        }

        const status = {
            status: 'complete',
            message: `Synced ${poolEventCount} pool events, ${aspEventCount} ASP membership events`,
            poolLeavesCount: await poolStore.getLeafCount(),
            aspMembershipLeavesCount: await aspMembershipStore.getLeafCount(),
            registeredPublicKeys: publicKeyCount,
            lastSyncedLedger: Math.max(
                metadata.poolSync.lastLedger,
                metadata.aspMembershipSync.lastLedger
            ),
            latestLedger,
            gap: 0,
            syncBroken: false,
            notesFound: scanResult?.found || 0,
            notesMarkedSpent: spentResult?.markedSpent || 0,
        };

        emit('syncComplete', status);
        emit('syncProgress', { phase: 'complete', progress: 100 });

        return status;
    } catch (error) {
        console.error('[SyncController] Sync failed:', error);
        return {
            status: 'error',
            message: error.message,
            syncBroken: false,
        };
    } finally {
        isSyncing = false;
    }
}

/**
 * Checks if the user has authenticated their keys.
 * @returns {boolean}
 */
export function hasAuthenticatedKeys() {
    return notesStore.hasAuthenticatedKeys();
}

/**
 * Initialize user's keypairs by prompting for Freighter signatures.
 * @returns {Promise<boolean>}
 */
export async function initializeUserKeys() {
    return notesStore.initializeKeypairs();
}

/**
 * Clear cached keypairs.
 */
export function clearUserKeys() {
    notesStore.clearKeypairCaches();
}

/**
 * Gets the current sync status without starting a sync.
 * @returns {Promise<SyncStatus>}
 */
export async function getSyncStatus() {
    const metadata = await getSyncMetadata();
    const latestLedger = await getLatestLedger();

    const lastSyncedLedger = Math.max(
        metadata?.poolSync?.lastLedger || 0,
        metadata?.aspMembershipSync?.lastLedger || 0
    );

    const gap = latestLedger - lastSyncedLedger;
    const syncBroken = metadata?.poolSync?.syncBroken ||
                       metadata?.aspMembershipSync?.syncBroken ||
                       false;

    let status = 'idle';
    if (isSyncing) {
        status = 'syncing';
    } else if (syncBroken) {
        status = 'broken';
    }

    return {
        status,
        poolLeavesCount: await poolStore.getLeafCount(),
        aspMembershipLeavesCount: await aspMembershipStore.getLeafCount(),
        lastSyncedLedger,
        latestLedger,
        gap,
        syncBroken,
        lastSuccessfulSync: metadata?.lastSuccessfulSync,
    };
}

/**
 * Checks if sync is currently in progress.
 * @returns {boolean}
 */
export function isSyncInProgress() {
    return isSyncing;
}

/**
 * Clears all synced data and resets metadata.
 * @returns {Promise<void>}
 */
export async function clearAndReset() {
    await poolStore.clear();
    await aspMembershipStore.clear();
    await publicKeyStore.clear();
    wasm().delete_sync_metadata(getNetwork().name);
    console.log('[SyncController] Cleared all data and reset sync state');
}

/**
 * Adds an event listener.
 * @param {string} event
 * @param {function} handler
 */
export function on(event, handler) {
    syncListeners.push({ event, handler });
}

/**
 * Removes an event listener.
 * @param {string} event
 * @param {function} handler
 */
export function off(event, handler) {
    syncListeners = syncListeners.filter(
        l => !(l.event === event && l.handler === handler)
    );
}

function emit(event, data) {
    for (const listener of syncListeners) {
        if (listener.event === event) {
            try {
                listener.handler(data);
            } catch (e) {
                console.error(`[SyncController] Event handler error (${event}):`, e);
            }
        }
    }
}

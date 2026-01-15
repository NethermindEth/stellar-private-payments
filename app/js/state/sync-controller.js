/**
 * Sync Controller - orchestrates event synchronization for Pool and ASP Membership.
 * Handles incremental sync, gap detection, progress reporting, and note discovery.
 * @module state/sync-controller
 */

import * as db from './db.js';
import * as poolStore from './pool-store.js';
import * as aspMembershipStore from './asp-membership-store.js';
import * as noteScanner from './note-scanner.js';
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
 * @property {number} gap - Ledger gap since last sync
 * @property {boolean} syncBroken - True if gap exceeds retention window
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
let userPrivateKey = null; // Stored for automatic note scanning

/**
 * Gets the current sync metadata from IndexedDB.
 * @returns {Promise<SyncMetadata|null>}
 */
export async function getSyncMetadata() {
    const network = getNetwork().name;
    return await db.get('sync_metadata', network);
}

/**
 * Saves sync metadata to IndexedDB.
 * @param {SyncMetadata} metadata
 * @returns {Promise<void>}
 */
async function saveSyncMetadata(metadata) {
    await db.put('sync_metadata', metadata);
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
 * Optionally scans for user notes and checks spent status if privateKey is provided.
 * 
 * @param {Object} [options]
 * @param {function} [options.onProgress] - Progress callback: (progress) => void
 * @param {Uint8Array} [options.privateKey] - User's private key for note scanning
 * @param {boolean} [options.scanNotes=true] - Whether to scan for new notes (if privateKey provided)
 * @param {boolean} [options.checkSpent=true] - Whether to check spent status (if privateKey provided)
 * @returns {Promise<SyncStatus>}
 */
export async function startSync(options = {}) {
    if (isSyncing) {
        return { status: 'syncing', message: 'Sync already in progress' };
    }
    
    isSyncing = true;
    const { onProgress, privateKey, scanNotes = true, checkSpent = true } = options;
    
    // Store private key for future syncs if provided
    if (privateKey) {
        userPrivateKey = privateKey;
    }
    
    try {
        let metadata = await getSyncMetadata() || createDefaultMetadata();
        const latestLedger = await getLatestLedger();
        const retentionConfig = await getRetentionConfig();
        
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
        
        // Determine start ledger for each contract
        const poolStartLedger = metadata.poolSync.lastLedger || 
            Math.max(1, latestLedger - retentionConfig.window);
        const aspStartLedger = metadata.aspMembershipSync.lastLedger || 
            Math.max(1, latestLedger - retentionConfig.window);
        
        emit('syncProgress', { phase: 'pool', progress: 0 });
        
        // Sync Pool events (streaming mode - events processed in onPage callback)
        let poolEventCount = 0;
        const poolResult = await fetchAllPoolEvents({
            startLedger: poolStartLedger,
            cursor: metadata.poolSync.lastCursor,
            onPage: async (events, cursor) => {
                await poolStore.processEvents(events);
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
        }
        
        emit('syncProgress', { phase: 'asp_membership', progress: 50 });
        
        // Sync ASP Membership events (streaming mode)
        let aspEventCount = 0;
        const aspResult = await fetchAllASPMembershipEvents({
            startLedger: aspStartLedger,
            cursor: metadata.aspMembershipSync.lastCursor,
            onPage: async (events, cursor) => {
                await aspMembershipStore.processEvents(events);
                aspEventCount += events.length;
                if (onProgress) {
                    onProgress({ phase: 'asp_membership', events: events.length, cursor });
                }
            },
        });
        
        if (aspResult.success) {
            metadata.aspMembershipSync.lastLedger = aspResult.latestLedger;
            metadata.aspMembershipSync.lastCursor = aspResult.cursor;
            metadata.aspMembershipSync.syncBroken = false;
        }
        
        // Update metadata
        metadata.lastSuccessfulSync = new Date().toISOString();
        await saveSyncMetadata(metadata);
        
        // Note scanning (if private key is available)
        let scanResult = null;
        let spentResult = null;
        const keyToUse = privateKey || userPrivateKey;
        
        if (keyToUse) {
            emit('syncProgress', { phase: 'note_scanning', progress: 75 });
            
            if (scanNotes) {
                scanResult = await noteScanner.scanForNotes(keyToUse, {
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
            
            emit('syncProgress', { phase: 'checking_spent', progress: 90 });
            
            if (checkSpent) {
                spentResult = await noteScanner.checkSpentNotes(keyToUse);
                
                if (spentResult.markedSpent > 0) {
                    emit('notesMarkedSpent', {
                        count: spentResult.markedSpent,
                    });
                }
            }
        }
        
        const status = {
            status: 'complete',
            message: `Synced ${poolEventCount} pool events, ${aspEventCount} ASP membership events`,
            poolLeavesCount: await poolStore.getLeafCount(),
            aspMembershipLeavesCount: await aspMembershipStore.getLeafCount(),
            lastSyncedLedger: Math.max(
                metadata.poolSync.lastLedger,
                metadata.aspMembershipSync.lastLedger
            ),
            latestLedger,
            gap: 0,
            syncBroken: false,
            // Note scanning results (if performed)
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
 * Sets the user's private key for automatic note scanning during syncs.
 * @param {Uint8Array|null} privateKey - Private key or null to clear
 */
export function setUserPrivateKey(privateKey) {
    userPrivateKey = privateKey;
}

/**
 * Checks if a user private key is set for automatic scanning.
 * @returns {boolean}
 */
export function hasUserPrivateKey() {
    return userPrivateKey !== null;
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
    await db.del('sync_metadata', getNetwork().name);
    console.log('[SyncController] Cleared all data and reset sync state');
}

/**
 * Adds an event listener.
 * @param {string} event - Event name
 * @param {function} handler - Event handler
 */
export function on(event, handler) {
    syncListeners.push({ event, handler });
}

/**
 * Removes an event listener.
 * @param {string} event - Event name
 * @param {function} handler - Event handler
 */
export function off(event, handler) {
    syncListeners = syncListeners.filter(
        l => !(l.event === event && l.handler === handler)
    );
}

/**
 * Emits an event to all listeners.
 * @param {string} event - Event name
 * @param {any} data - Event data
 */
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

/**
 * StateManager - unified API for client-side state management.
 * Coordinates IndexedDB storage, event sync, and merkle tree operations.
 * @module state
 */

import * as db from './db.js';
import * as poolStore from './pool-store.js';
import * as aspMembershipStore from './asp-membership-store.js';
import * as aspNonMembershipFetcher from './asp-non-membership-fetcher.js';
import * as notesStore from './notes-store.js';
import * as syncController from './sync-controller.js';
import * as noteScanner from './note-scanner.js';
import { getRetentionConfig, detectRetentionWindow, ledgersToDuration } from './retention-verifier.js';

let initialized = false;
let retentionConfig = null;
let eventListeners = [];
let forwardedSyncListeners = [];

/**
 * StateManager provides a unified API for all client-side state operations.
 */
export const StateManager = {
    /**
     * Initializes the state management system.
     * Opens IndexedDB, detects RPC retention window, and initializes all stores.
     * @returns {Promise<void>}
     */
    async initialize() {
        if (initialized) {
            console.log('[StateManager] Already initialized');
            return;
        }

        console.log('[StateManager] Initializing...');

        // Initialize database
        await db.init();

        // Detect retention window
        retentionConfig = await getRetentionConfig();
        console.log(`[StateManager] RPC retention: ${retentionConfig.description}`);
        emit('retentionDetected', retentionConfig);

        // Initialize stores
        await poolStore.init();
        await aspMembershipStore.init();

        // Forward sync events (store references for cleanup)
        const progressHandler = data => emit('syncProgress', data);
        const completeHandler = data => emit('syncComplete', data);
        const brokenHandler = data => emit('syncBroken', data);
        const notesDiscoveredHandler = data => emit('notesDiscovered', data);
        const notesMarkedSpentHandler = data => emit('notesMarkedSpent', data);
        
        syncController.on('syncProgress', progressHandler);
        syncController.on('syncComplete', completeHandler);
        syncController.on('syncBroken', brokenHandler);
        syncController.on('notesDiscovered', notesDiscoveredHandler);
        syncController.on('notesMarkedSpent', notesMarkedSpentHandler);
        
        // Forward note scanner events
        const noteDiscoveredHandler = data => emit('noteDiscovered', data);
        const noteSpentHandler = data => emit('noteSpent', data);
        noteScanner.on('noteDiscovered', noteDiscoveredHandler);
        noteScanner.on('noteSpent', noteSpentHandler);
        
        forwardedSyncListeners = [
            ['syncProgress', progressHandler, syncController],
            ['syncComplete', completeHandler, syncController],
            ['syncBroken', brokenHandler, syncController],
            ['notesDiscovered', notesDiscoveredHandler, syncController],
            ['notesMarkedSpent', notesMarkedSpentHandler, syncController],
            ['noteDiscovered', noteDiscoveredHandler, noteScanner],
            ['noteSpent', noteSpentHandler, noteScanner],
        ];

        initialized = true;
        console.log('[StateManager] Initialized');
    },

    /**
     * Checks if the state manager is initialized.
     * @returns {boolean}
     */
    isInitialized() {
        return initialized;
    },

    // Retention

    /**
     * Gets the detected RPC retention configuration.
     * @returns {Object|null}
     */
    getRetentionConfig() {
        return retentionConfig;
    },

    /**
     * Forces re-detection of the RPC retention window.
     * @returns {Promise<Object>}
     */
    async refreshRetentionConfig() {
        retentionConfig = await detectRetentionWindow();
        emit('retentionDetected', retentionConfig);
        return retentionConfig;
    },

    // Sync

    /**
     * Starts synchronization of Pool and ASP Membership events.
     * Optionally performs note scanning if a private key is provided.
     * 
     * @param {Object} [options]
     * @param {function} [options.onProgress] - Progress callback
     * @param {Uint8Array} [options.privateKey] - User's private key for note scanning
     * @param {boolean} [options.scanNotes=true] - Scan for new notes (if privateKey provided)
     * @param {boolean} [options.checkSpent=true] - Check spent status (if privateKey provided)
     * @returns {Promise<Object>} Sync status including notesFound and notesMarkedSpent
     */
    async startSync(options) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return syncController.startSync(options);
    },

    /**
     * Gets the current sync status.
     * @returns {Promise<Object>}
     */
    async getSyncStatus() {
        return syncController.getSyncStatus();
    },

    /**
     * Checks the sync gap against the retention window.
     * @returns {Promise<Object>}
     */
    async checkSyncGap() {
        return syncController.checkSyncGap();
    },

    /**
     * Checks if sync is broken (gap exceeds retention window).
     * @returns {Promise<boolean>}
     */
    async isSyncBroken() {
        const status = await syncController.getSyncStatus();
        return status.syncBroken;
    },

    // Pool

    /**
     * Gets the current pool merkle root.
     * @returns {Uint8Array|null}
     */
    getPoolRoot() {
        return poolStore.getRoot();
    },

    /**
     * Gets a merkle proof for a pool commitment.
     * @param {number} leafIndex - Leaf index
     * @returns {Object|null}
     */
    getPoolMerkleProof(leafIndex) {
        return poolStore.getMerkleProof(leafIndex);
    },

    /**
     * Checks if a nullifier has been spent.
     * @param {string|Uint8Array} nullifier
     * @returns {Promise<boolean>}
     */
    async isNullifierSpent(nullifier) {
        return poolStore.isNullifierSpent(nullifier);
    },

    /**
     * Gets the next pool leaf index.
     * @returns {number}
     */
    getPoolNextIndex() {
        return poolStore.getNextIndex();
    },

    /**
     * Rebuilds the pool merkle tree from database.
     * Call after sync to ensure tree matches stored leaves.
     * @returns {Promise<number>} Number of leaves in rebuilt tree
     */
    async rebuildPoolTree() {
        return poolStore.rebuildTree();
    },

    // ASP Membership

    /**
     * Gets the current ASP membership merkle root.
     * @returns {Uint8Array|null}
     */
    getASPMembershipRoot() {
        return aspMembershipStore.getRoot();
    },

    /**
     * Gets a merkle proof for an ASP membership leaf.
     * @param {number} leafIndex - Leaf index
     * @returns {Promise<Object|null>}
     */
    async getASPMembershipProof(leafIndex) {
        return aspMembershipStore.getMerkleProof(leafIndex);
    },

    /**
     * Finds a user's membership leaf by its hash and returns the index.
     * @param {string|Uint8Array} leafHash - The membership leaf hash
     * @returns {Promise<{index: number, leaf: string}|null>}
     */
    async findASPMembershipLeaf(leafHash) {
        return aspMembershipStore.findLeafByHash(leafHash);
    },

    /**
     * Gets the total count of ASP membership leaves.
     * @returns {Promise<number>}
     */
    async getASPMembershipLeafCount() {
        return aspMembershipStore.getLeafCount();
    },

    // ASP Non-Membership (on-demand)

    /**
     * Fetches a non-membership proof from the contract (on-demand).
     * @param {Uint8Array|string} key - Key to prove non-membership for
     * @returns {Promise<Object>}
     */
    async getASPNonMembershipProof(key) {
        return aspNonMembershipFetcher.fetchNonMembershipProof(key);
    },

    /**
     * Fetches the current ASP non-membership root.
     * @returns {Promise<Object>}
     */
    async getASPNonMembershipRoot() {
        return aspNonMembershipFetcher.fetchRoot();
    },

    // Notes

    /**
     * Gets all user notes.
     * @param {Object} [options]
     * @param {boolean} [options.unspentOnly] - Only return unspent notes
     * @returns {Promise<Array>}
     */
    async getUserNotes(options) {
        return notesStore.getNotes(options);
    },

    /**
     * Gets unspent notes for transaction inputs.
     * @returns {Promise<Array>}
     */
    async getUnspentNotes() {
        return notesStore.getUnspentNotes();
    },

    /**
     * Gets total balance of unspent notes.
     * @returns {Promise<bigint>}
     */
    async getBalance() {
        return notesStore.getBalance();
    },

    /**
     * Saves a new note.
     * @param {Object} params - Note parameters
     * @returns {Promise<Object>}
     */
    async saveNote(params) {
        return notesStore.saveNote(params);
    },

    /**
     * Marks a note as spent.
     * @param {string} commitment - Note commitment
     * @param {number} ledger - Ledger when spent
     * @returns {Promise<boolean>}
     */
    async markNoteSpent(commitment, ledger) {
        return notesStore.markNoteSpent(commitment, ledger);
    },

    /**
     * Exports notes to a JSON file.
     * @returns {Promise<Blob>}
     */
    async exportNotes() {
        return notesStore.exportNotes();
    },

    /**
     * Imports notes from a JSON file.
     * @param {File|Blob} file - Notes JSON file
     * @returns {Promise<number>} Number of notes imported
     */
    async importNotes(file) {
        return notesStore.importNotes(file);
    },

    // Note Scanning / User Authentication

    /**
     * Checks if the user has authenticated their keypairs for note scanning.
     * Keys are derived from Freighter signatures and cached in memory.
     * @returns {boolean}
     */
    hasAuthenticatedKeys() {
        return syncController.hasAuthenticatedKeys();
    },

    /**
     * Initialize user's keypairs by prompting for Freighter signatures.
     * Call this when the user "logs in" to enable note scanning.
     * @returns {Promise<boolean>} True if keypairs were successfully derived
     */
    async initializeUserKeys() {
        return syncController.initializeUserKeys();
    },

    /**
     * Clear cached keypairs.
     */
    clearUserKeys() {
        syncController.clearUserKeys();
    },

    /**
     * Scans encrypted outputs to find notes belonging to the user.
     * This is useful for discovering notes received from others.
     * 
     * @param {Uint8Array} privateKey - User's private key
     * @param {Object} [options] - Scan options
     * @param {boolean} [options.fullRescan=false] - Rescan all outputs, not just new ones
     * @param {function} [options.onProgress] - Progress callback (scanned, total)
     * @returns {Promise<{scanned: number, found: number, notes: Array, alreadyKnown: number}>}
     */
    async scanForNotes(privateKey, options) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return noteScanner.scanForNotes(privateKey, options);
    },

    /**
     * Checks if any user notes have been spent and updates their status.
     * @param {Uint8Array} privateKey - User's private key
     * @returns {Promise<{checked: number, markedSpent: number}>}
     */
    async checkSpentNotes(privateKey) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return noteScanner.checkSpentNotes(privateKey);
    },

    /**
     * Derives the nullifier for a note (for verification purposes).
     * @param {Uint8Array} privateKey - Note's private key
     * @param {Uint8Array} commitment - Note commitment
     * @param {number} leafIndex - Leaf index in merkle tree
     * @returns {Uint8Array} Nullifier hash
     */
    deriveNullifier(privateKey, commitment, leafIndex) {
        return noteScanner.deriveNullifierForNote(privateKey, commitment, leafIndex);
    },

    // Events

    /**
     * Adds an event listener.
     * 
     * Events:
     * - syncProgress: { phase, progress, ... } - Sync progress updates
     * - syncComplete: { status, poolLeavesCount, ... } - Sync completed
     * - syncBroken: { message, gap } - Sync gap exceeds retention
     * - retentionDetected: { window, description, ... } - RPC retention detected
     * - notesDiscovered: { found, notes } - New notes found during sync
     * - notesMarkedSpent: { count } - Notes marked spent during sync
     * - noteDiscovered: { note } - Individual note discovered
     * - noteSpent: { commitment, ledger } - Individual note marked spent
     * 
     * @param {string} event - Event name
     * @param {function} handler - Event handler
     */
    on(event, handler) {
        eventListeners.push({ event, handler });
    },

    /**
     * Removes an event listener.
     * @param {string} event - Event name
     * @param {function} handler - Event handler
     */
    off(event, handler) {
        eventListeners = eventListeners.filter(
            l => !(l.event === event && l.handler === handler)
        );
    },

    // Utilities

    /**
     * Clears all state and resets to fresh start.
     * Use with caution - this will delete all synced data and notes.
     * @returns {Promise<void>}
     */
    async clearAll() {
        await syncController.clearAndReset();
        await notesStore.clear();
        console.log('[StateManager] All data cleared');
    },

    /**
     * Debug: Show all pool leaves stored in IndexedDB.
     * @returns {Promise<void>}
     */
    async debugPoolLeaves() {
        return poolStore.debugShowAllLeaves();
    },

    /**
     * Debug: Get all pool leaf indices.
     * @returns {Promise<number[]>}
     */
    async getPoolLeafIndices() {
        return poolStore.getAllLeafIndices();
    },

    /**
     * Closes the database connection and cleans up listeners.
     */
    close() {
        for (const [event, handler, source] of forwardedSyncListeners) {
            source.off(event, handler);
        }
        forwardedSyncListeners = [];

        // Force clean of StateManager's own listeners
        eventListeners = [];
        
        syncController.clearUserKeys();
        db.close();
        initialized = false;
    },

    /**
     * Converts ledger count to human-readable duration.
     * @param {number} ledgers
     * @returns {string}
     */
    ledgersToDuration,
};

/**
 * Emits an event to all listeners.
 * @param {string} event
 * @param {any} data
 */
function emit(event, data) {
    for (const listener of eventListeners) {
        if (listener.event === event) {
            try {
                listener.handler(data);
            } catch (e) {
                console.error(`[StateManager] Event handler error (${event}):`, e);
            }
        }
    }
}

export default StateManager;

// Re-export sub-modules for direct access if needed
export { db, poolStore, aspMembershipStore, aspNonMembershipFetcher, notesStore, syncController, noteScanner };

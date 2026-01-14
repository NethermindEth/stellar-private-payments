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
import { getRetentionConfig, detectRetentionWindow, ledgersToDuration } from './retention-verifier.js';

let initialized = false;
let retentionConfig = null;
let eventListeners = [];

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

        // Forward sync events
        syncController.on('syncProgress', data => emit('syncProgress', data));
        syncController.on('syncComplete', data => emit('syncComplete', data));
        syncController.on('syncBroken', data => emit('syncBroken', data));

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
     * @param {Object} [options]
     * @param {function} [options.onProgress] - Progress callback
     * @returns {Promise<Object>} Sync status
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
     * @returns {Object|null}
     */
    getASPMembershipProof(leafIndex) {
        return aspMembershipStore.getMerkleProof(leafIndex);
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
     * Exports notes to an encrypted file.
     * @param {string} password - Encryption password
     * @returns {Promise<Blob>}
     */
    async exportNotes(password) {
        return notesStore.exportNotes(password);
    },

    /**
     * Imports notes from an encrypted file.
     * @param {File|Blob} file - Encrypted notes file
     * @param {string} password - Decryption password
     * @returns {Promise<number>} Number of notes imported
     */
    async importNotes(file, password) {
        return notesStore.importNotes(file, password);
    },

    // Events

    /**
     * Adds an event listener.
     * Events: syncProgress, syncComplete, syncBroken, retentionDetected
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
     * Closes the database connection.
     */
    close() {
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
export { db, poolStore, aspMembershipStore, aspNonMembershipFetcher, notesStore, syncController };

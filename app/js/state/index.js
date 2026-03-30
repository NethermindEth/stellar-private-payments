/**
 * StateManager - unified API for client-side state management.
 * Coordinates storage, event sync, and merkle tree operations.
 *
 * @module state
 */

import * as wasmBridge from './wasm.js';
import { get as wasm } from './wasm.js';
import * as aspNonMembershipFetcher from './asp-non-membership-fetcher.js';
import * as notesStore from './notes-store.js';
import * as publicKeyStore from './public-key-store.js';
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
     * Opens the database, detects RPC retention, and wires up events.
     * @returns {Promise<void>}
     */
    async initialize() {
        if (initialized) {
            console.log('[StateManager] Already initialized');
            return;
        }

        console.log('[StateManager] Initializing...');

        await wasmBridge.init();

        // Detect retention window
        retentionConfig = await getRetentionConfig();
        console.log(`[StateManager] RPC retention: ${retentionConfig.description}`);
        emit('retentionDetected', retentionConfig);

        await publicKeyStore.init();

        // Forward sync events
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

        // Forward public key events
        const publicKeyRegisteredHandler = data => emit('publicKeyRegistered', data);
        publicKeyStore.on('publicKeyRegistered', publicKeyRegisteredHandler);

        forwardedSyncListeners = [
            ['syncProgress', progressHandler, syncController],
            ['syncComplete', completeHandler, syncController],
            ['syncBroken', brokenHandler, syncController],
            ['notesDiscovered', notesDiscoveredHandler, syncController],
            ['notesMarkedSpent', notesMarkedSpentHandler, syncController],
            ['noteDiscovered', noteDiscoveredHandler, noteScanner],
            ['noteSpent', noteSpentHandler, noteScanner],
            ['publicKeyRegistered', publicKeyRegisteredHandler, publicKeyStore],
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

    getRetentionConfig() {
        return retentionConfig;
    },

    async refreshRetentionConfig() {
        retentionConfig = await detectRetentionWindow();
        emit('retentionDetected', retentionConfig);
        return retentionConfig;
    },

    // Sync

    async startSync(options) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return syncController.startSync(options);
    },

    async getSyncStatus() {
        return syncController.getSyncStatus();
    },

    async checkSyncGap() {
        return syncController.checkSyncGap();
    },

    async isSyncBroken() {
        const status = await syncController.getSyncStatus();
        return status.syncBroken;
    },

    // Pool

    getPoolRoot() {
        return new Uint8Array(wasm().get_pool_root());
    },

    getPoolMerkleProof(leafIndex) {
        try {
            if (!Number.isInteger(leafIndex) || leafIndex < 0) return null;
            if (leafIndex >= wasm().get_pool_next_index()) return null;
            return wasm().get_pool_merkle_proof(leafIndex);
        } catch (e) {
            console.error('[StateManager] Failed to get pool merkle proof:', e);
            return null;
        }
    },

    async isNullifierSpent(nullifier) {
        const hex = typeof nullifier === 'string' ? nullifier : ('0x' + Array.from(nullifier).map(b => b.toString(16).padStart(2, '0')).join(''));
        return wasm().is_nullifier_spent(hex);
    },

    getPoolNextIndex() {
        return wasm().get_pool_next_index();
    },

    async rebuildPoolTree() {
        return wasm().rebuild_pool_tree();
    },

    // ASP Membership

    getASPMembershipRoot() {
        return new Uint8Array(wasm().get_asp_membership_root());
    },

    async getASPMembershipProof(leafIndex) {
        try {
            if (!Number.isInteger(leafIndex) || leafIndex < 0) return null;
            if (leafIndex >= wasm().get_asp_membership_next_index()) return null;
            return wasm().get_asp_membership_proof(leafIndex);
        } catch (e) {
            console.error('[StateManager] Failed to get ASP membership proof:', e);
            return null;
        }
    },

    async findASPMembershipLeaf(leafHash) {
        try {
            const hex = typeof leafHash === 'string' ? leafHash : ('0x' + Array.from(leafHash).map(b => b.toString(16).padStart(2, '0')).join(''));
            return JSON.parse(wasm().find_asp_membership_leaf(hex));
        } catch (e) {
            console.error('[StateManager] Failed to find ASP membership leaf:', e);
            return null;
        }
    },

    async getASPMembershipLeafCount() {
        return wasm().get_asp_membership_leaf_count();
    },

    // ASP Non-Membership (on-demand, pure RPC)

    async getASPNonMembershipProof(key) {
        return aspNonMembershipFetcher.fetchNonMembershipProof(key);
    },

    async getASPNonMembershipRoot() {
        return aspNonMembershipFetcher.fetchRoot();
    },

    // Address Book (Public Keys)

    async getPublicKeyByAddress(address) {
        return publicKeyStore.getByAddress(address);
    },

    async searchPublicKey(address) {
        return publicKeyStore.searchByAddress(address);
    },

    async getRecentPublicKeys(limit = 20) {
        return publicKeyStore.getRecentRegistrations(limit);
    },

    async getPublicKeyCount() {
        return publicKeyStore.getCount();
    },

    // Notes

    async getUserNotes(options) {
        return notesStore.getNotes(options);
    },

    async getUnspentNotes() {
        return notesStore.getUnspentNotes();
    },

    async getBalance() {
        return notesStore.getBalance();
    },

    async saveNote(params) {
        return notesStore.saveNote(params);
    },

    async markNoteSpent(commitment, ledger) {
        return notesStore.markNoteSpent(commitment, ledger);
    },

    async exportNotes() {
        return notesStore.exportNotes();
    },

    async importNotes(file) {
        return notesStore.importNotes(file);
    },

    // Note Scanning / User Authentication

    hasAuthenticatedKeys() {
        return syncController.hasAuthenticatedKeys();
    },

    async initializeUserKeys() {
        return syncController.initializeUserKeys();
    },

    clearUserKeys() {
        syncController.clearUserKeys();
    },

    async scanForNotes(privateKey, options) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return noteScanner.scanForNotes(options);
    },

    async checkSpentNotes(privateKey) {
        if (!initialized) {
            throw new Error('StateManager not initialized');
        }
        return noteScanner.checkSpentNotes();
    },

    deriveNullifier(privateKey, commitment, leafIndex) {
        return noteScanner.deriveNullifierForNote(privateKey, commitment, leafIndex);
    },

    // Events

    on(event, handler) {
        eventListeners.push({ event, handler });
    },

    off(event, handler) {
        eventListeners = eventListeners.filter(
            l => !(l.event === event && l.handler === handler)
        );
    },

    // Utilities

    async clearAll() {
        await syncController.clearAndReset();
        await notesStore.clear();
        console.log('[StateManager] All data cleared');
    },

    async forceResetDatabase() {
        console.log('[StateManager] Force resetting database...');
        wasm().clear_all();
        await publicKeyStore.init();
        console.log('[StateManager] Database force reset complete - sync required');
    },

    close() {
        for (const [event, handler, source] of forwardedSyncListeners) {
            source.off(event, handler);
        }
        forwardedSyncListeners = [];
        eventListeners = [];
        syncController.clearUserKeys();
        initialized = false;
    },

    ledgersToDuration,
};

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
export { aspNonMembershipFetcher, notesStore, publicKeyStore, syncController, noteScanner };

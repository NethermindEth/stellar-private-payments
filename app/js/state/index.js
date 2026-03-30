/**
 * StateManager - unified API for client-side state management.
 * Coordinates WASM storage, event sync, and merkle tree operations.
 *
 * The Rust WASM StateManager handles all persistent storage and Merkle trees.
 * JS manages events, key derivation (Freighter), RPC calls (Stellar SDK), and UI.
 *
 * @module state
 */

import * as wasmBridge from './wasm.js';
import * as poolStore from './pool-store.js';
import * as aspMembershipStore from './asp-membership-store.js';
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
     * Loads the WASM module, opens SQLite, detects RPC retention, and wires up events.
     * @returns {Promise<void>}
     */
    async initialize() {
        if (initialized) {
            console.log('[StateManager] Already initialized');
            return;
        }

        console.log('[StateManager] Initializing...');

        // Initialize WASM state module (opens SQLite, rebuilds Merkle trees)
        await wasmBridge.init();

        // Detect retention window
        retentionConfig = await getRetentionConfig();
        console.log(`[StateManager] RPC retention: ${retentionConfig.description}`);
        emit('retentionDetected', retentionConfig);

        // Sub-store init() are now lightweight (tree already built by WASM constructor)
        await poolStore.init();
        await aspMembershipStore.init();
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
        return poolStore.getRoot();
    },

    getPoolMerkleProof(leafIndex) {
        return poolStore.getMerkleProof(leafIndex);
    },

    async isNullifierSpent(nullifier) {
        return poolStore.isNullifierSpent(nullifier);
    },

    getPoolNextIndex() {
        return poolStore.getNextIndex();
    },

    async rebuildPoolTree() {
        return poolStore.rebuildTree();
    },

    // ASP Membership

    getASPMembershipRoot() {
        return aspMembershipStore.getRoot();
    },

    async getASPMembershipProof(leafIndex) {
        return aspMembershipStore.getMerkleProof(leafIndex);
    },

    async findASPMembershipLeaf(leafHash) {
        return aspMembershipStore.findLeafByHash(leafHash);
    },

    async getASPMembershipLeafCount() {
        return aspMembershipStore.getLeafCount();
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
        const w = wasmBridge.get();
        w.clear_all();
        // Sub-store init after reset
        await poolStore.init();
        await aspMembershipStore.init();
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
export { poolStore, aspMembershipStore, aspNonMembershipFetcher, notesStore, publicKeyStore, syncController, noteScanner };

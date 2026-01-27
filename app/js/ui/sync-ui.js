/**
 * Sync Status UI - shows state synchronization progress.
 * @module ui/sync-ui
 */

import { StateManager } from '../state/index.js';
import { Toast } from './core.js';

export const SyncUI = {
    statusEl: null,
    messageEl: null,
    progressEl: null,
    warningEl: null,

    init() {
        this.createSyncIndicator();
        
        StateManager.on('syncProgress', (data) => this.onProgress(data));
        StateManager.on('syncComplete', (data) => this.onComplete(data));
        StateManager.on('syncBroken', (data) => this.onBroken(data));
        StateManager.on('retentionDetected', (data) => this.onRetentionDetected(data));
    },

    createSyncIndicator() {
        if (document.getElementById('sync-status')) {
            this.statusEl = document.getElementById('sync-status');
            this.messageEl = document.getElementById('sync-message');
            this.progressEl = document.getElementById('sync-progress');
            this.warningEl = document.getElementById('sync-warning');
            return;
        }

        const syncBar = document.createElement('div');
        syncBar.id = 'sync-status';
        syncBar.className = 'fixed bottom-4 right-4 bg-gray-800 border border-gray-700 rounded-lg p-3 shadow-lg max-w-xs z-50 hidden';
        syncBar.innerHTML = `
            <div class="flex items-center gap-2">
                <div id="sync-spinner" class="animate-spin w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full hidden"></div>
                <span id="sync-message" class="text-sm text-gray-300">Syncing...</span>
            </div>
            <div id="sync-progress" class="mt-2 h-1 bg-gray-700 rounded overflow-hidden hidden">
                <div class="h-full bg-emerald-500 transition-all duration-300" style="width: 0%"></div>
            </div>
        `;
        document.body.appendChild(syncBar);

        const warningBanner = document.createElement('div');
        warningBanner.id = 'sync-warning';
        warningBanner.className = 'fixed top-0 left-0 right-0 bg-amber-900/90 border-b border-amber-700 p-3 text-center hidden z-50';
        warningBanner.innerHTML = `
            <div class="flex items-center justify-center gap-2">
                <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <span id="sync-warning-text" class="text-amber-200 text-sm"></span>
                <button id="sync-warning-close" class="ml-4 text-amber-400 hover:text-amber-200">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        `;
        document.body.appendChild(warningBanner);

        this.statusEl = syncBar;
        this.messageEl = document.getElementById('sync-message');
        this.progressEl = document.getElementById('sync-progress');
        this.warningEl = warningBanner;

        document.getElementById('sync-warning-close')?.addEventListener('click', () => {
            this.warningEl.classList.add('hidden');
        });
    },

    show(message, showSpinner = true) {
        if (!this.statusEl) return;
        this.statusEl.classList.remove('hidden');
        this.messageEl.textContent = message;
        const spinner = document.getElementById('sync-spinner');
        if (spinner) {
            spinner.classList.toggle('hidden', !showSpinner);
        }
    },

    hide() {
        if (!this.statusEl) return;
        setTimeout(() => {
            this.statusEl.classList.add('hidden');
        }, 2000);
    },

    setProgress(percent) {
        if (!this.progressEl) return;
        this.progressEl.classList.remove('hidden');
        const bar = this.progressEl.querySelector('div');
        if (bar) bar.style.width = `${percent}%`;
    },

    showWarning(message) {
        if (!this.warningEl) return;
        document.getElementById('sync-warning-text').textContent = message;
        this.warningEl.classList.remove('hidden');
    },

    hideWarning() {
        if (!this.warningEl) return;
        this.warningEl.classList.add('hidden');
    },

    onProgress(data) {
        const messages = {
            pool: 'Syncing pool events...',
            asp_membership: 'Syncing ASP membership...',
            complete: 'Sync complete!',
        };
        this.show(messages[data.phase] || 'Syncing...');
        if (data.progress !== undefined) {
            this.setProgress(data.progress);
        }
    },

    onComplete(data) {
        this.show(`Synced: ${data.poolLeavesCount} pool, ${data.aspMembershipLeavesCount} ASP`, false);
        this.hide();
        this.hideWarning();
        Toast.show('State synchronized successfully', 'success');
    },

    onBroken(data) {
        this.showWarning(data.message);
        Toast.show('Sync gap detected - some notes may be inaccessible', 'error');
    },

    onRetentionDetected(config) {
        console.log(`[SyncUI] RPC retention: ${config.description}`);
    },

    async startSync() {
        this.show('Starting sync...');
        try {
            // Only scan notes if keys are already authenticated (from previous action)
            // Don't prompt for authentication during regular sync
            const keysInitialized = StateManager.hasAuthenticatedKeys();
            
            const status = await StateManager.startSync({
                onProgress: (p) => this.onProgress(p),
                forceRefresh: true,
                scanNotes: keysInitialized,
                checkSpent: keysInitialized,
            });
            await StateManager.rebuildPoolTree();
            
            if (status.status === 'broken') {
                this.showWarning(status.message);
            } else if (status.status === 'complete') {
                let msg = `Synced: ${status.poolLeavesCount} pool leaves`;
                if (status.notesFound > 0) {
                    msg += `, found ${status.notesFound} new note(s)!`;
                    Toast.show(msg, 'success');
                }
                if (status.notesMarkedSpent > 0) {
                    console.log(`[SyncUI] Marked ${status.notesMarkedSpent} notes as spent`);
                }
            }
        } catch (err) {
            console.error('[SyncUI] Sync failed:', err);
            Toast.show('Sync failed: ' + err.message, 'error');
            this.hide();
        }
    },
    
    /**
     * Scans for notes received from others.
     * Requires authenticated keys.
     */
    async scanForNotes() {
        this.show('Checking authentication...');
        try {
            let keysInitialized = StateManager.hasAuthenticatedKeys();
            if (!keysInitialized) {
                this.show('Authenticating for note scanning...');
                keysInitialized = await StateManager.initializeUserKeys();
                if (!keysInitialized) {
                    Toast.show('Authentication required to scan for notes', 'error');
                    this.hide();
                    return;
                }
            }
            
            this.show('Scanning for received notes...');
            const result = await StateManager.startSync({
                onProgress: (p) => this.onProgress(p),
                forceRefresh: false,
                scanNotes: true,
                checkSpent: true,
            });
            
            if (result.notesFound > 0) {
                Toast.show(`Found ${result.notesFound} new note(s)!`, 'success');
            } else {
                Toast.show('No new notes found', 'info');
            }
            
            this.hide();
        } catch (err) {
            console.error('[SyncUI] Scan failed:', err);
            Toast.show('Scan failed: ' + err.message, 'error');
            this.hide();
        }
    },

    async checkGap() {
        const gap = await StateManager.checkSyncGap();
        if (gap.status === 'warning') {
            this.showWarning(gap.message);
        } else if (gap.status === 'broken') {
            this.showWarning(gap.message);
        }
    },

    async forceResync() {
        if (!confirm('This will clear all cached state and re-sync from scratch. Continue?')) {
            return;
        }
        
        this.show('Clearing cached state...');
        try {
            await StateManager.clearAll();
            console.log('[SyncUI] State cleared, starting fresh sync...');
            
            // Only scan notes if keys are already authenticated
            // Don't prompt for authentication during resync
            const keysInitialized = StateManager.hasAuthenticatedKeys();
            
            this.show('Re-syncing from scratch...');
            const status = await StateManager.startSync({
                onProgress: (p) => this.onProgress(p),
                forceRefresh: true,
                scanNotes: keysInitialized,
                checkSpent: keysInitialized,
            });
            await StateManager.rebuildPoolTree();
            
            if (status.status === 'complete') {
                let msg = `Resynced: ${status.aspMembershipLeavesCount} ASP membership, ${status.poolLeavesCount} pool leaves`;
                if (status.notesFound > 0) {
                    msg += `, found ${status.notesFound} note(s)`;
                }
                Toast.show(msg, 'success');
            } else if (status.status === 'broken') {
                this.showWarning(status.message);
            }
        } catch (err) {
            console.error('[SyncUI] Force resync failed:', err);
            Toast.show('Force resync failed: ' + err.message, 'error');
            this.hide();
        }
    }
};

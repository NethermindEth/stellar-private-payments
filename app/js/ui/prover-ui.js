/**
 * Prover Initialization UI - shows prover loading status.
 * @module ui/prover-ui
 */

import * as ProverClient from '../prover-client.js';
import { Toast } from './core.js';

export const ProverUI = {
    statusEl: null,
    progressEl: null,
    isInitializing: false,

    createStatusIndicator() {
        if (document.getElementById('prover-status')) {
            this.statusEl = document.getElementById('prover-status');
            this.progressEl = document.getElementById('prover-progress');
            return;
        }

        const statusBar = document.createElement('div');
        statusBar.id = 'prover-status';
        statusBar.className = 'fixed bottom-4 left-4 bg-dark-800 border border-dark-700 rounded-lg p-3 shadow-lg max-w-xs z-40';
        statusBar.innerHTML = `
            <div class="flex items-center gap-2">
                <div id="prover-spinner" class="w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin"></div>
                <span id="prover-message" class="text-sm text-dark-300">Initializing prover...</span>
            </div>
            <div id="prover-progress" class="mt-2 h-1 bg-dark-700 rounded overflow-hidden">
                <div class="h-full bg-brand-500 transition-all duration-300" style="width: 0%"></div>
            </div>
        `;
        document.body.appendChild(statusBar);

        this.statusEl = statusBar;
        this.progressEl = document.getElementById('prover-progress');
    },

    setMessage(message, showSpinner = true) {
        if (!this.statusEl) return;
        const msgEl = document.getElementById('prover-message');
        const spinnerEl = document.getElementById('prover-spinner');
        if (msgEl) msgEl.textContent = message;
        if (spinnerEl) spinnerEl.classList.toggle('hidden', !showSpinner);
    },

    setProgress(percent) {
        if (!this.progressEl) return;
        const bar = this.progressEl.querySelector('div');
        if (bar) bar.style.width = `${percent}%`;
    },

    showReady() {
        if (!this.statusEl) return;
        this.setMessage('Prover ready', false);
        this.setProgress(100);
        this.statusEl.classList.add('border-emerald-500/30');
        
        setTimeout(() => {
            if (this.statusEl) {
                this.statusEl.style.opacity = '0';
                this.statusEl.style.transform = 'translateX(-100%)';
                setTimeout(() => {
                    if (this.statusEl) {
                        this.statusEl.classList.add('hidden');
                        this.statusEl.style.opacity = '';
                        this.statusEl.style.transform = '';
                    }
                }, 300);
            }
        }, 2000);
    },

    showError(error) {
        if (!this.statusEl) return;
        this.setMessage(`Error: ${error}`, false);
        this.statusEl.classList.add('border-red-500/30');
        const spinnerEl = document.getElementById('prover-spinner');
        if (spinnerEl) spinnerEl.classList.add('hidden');
    },

    async initialize() {
        if (this.isInitializing || ProverClient.isReady()) {
            return;
        }

        this.isInitializing = true;
        this.createStatusIndicator();

        const unsubscribe = ProverClient.onProgress((loaded, total, message, percent) => {
            this.setMessage(message || 'Downloading artifacts...');
            this.setProgress(percent || 0);
        });

        try {
            const cached = await ProverClient.isCached();
            if (cached) {
                this.setMessage('Loading from cache...');
            } else {
                this.setMessage('Downloading proving key...');
            }

            await ProverClient.initializeProver();
            this.showReady();
            console.log('[ProverUI] Prover initialized successfully');
        } catch (e) {
            console.error('[ProverUI] Prover initialization failed:', e);
            this.showError(e.message);
        } finally {
            unsubscribe();
            this.isInitializing = false;
        }
    },

    isReady() {
        return ProverClient.isReady();
    },

    async ensureReady() {
        if (ProverClient.isReady()) {
            return true;
        }

        Toast.show('Initializing ZK prover...', 'success');
        await this.initialize();
        return ProverClient.isReady();
    }
};

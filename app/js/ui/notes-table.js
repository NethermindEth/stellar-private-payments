/**
 * Notes Table - displays user notes with filtering and actions.
 * @module ui/notes-table
 */

import { getHandle } from '../wasm-facade.js';
import { App, Toast } from './core.js';
import { Templates } from './templates.js';

export const NotesTable = {
    filter: 'all',
    _timer: null,
    _refreshing: false,
    
    init() {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.filter = btn.dataset.filter;
                
                document.querySelectorAll('.filter-btn').forEach(b => {
                    const isActive = b === btn;
                    b.setAttribute('aria-selected', isActive);
                    b.classList.toggle('bg-dark-700', isActive);
                    b.classList.toggle('text-dark-50', isActive);
                    b.classList.toggle('text-dark-400', !isActive);
                });
                
                this.render();
            });
        });
        
        this.render();

        App.events.addEventListener('wallet:ready', () => {
            this.startPolling();
        });
        App.events.addEventListener('wallet:disconnected', () => {
            this.stopPolling();
            App.state.notes = [];
            this.render();
        });
    },
    
    /**
     * Reloads notes from storage and re-renders the table.
     * Call this when the account changes to show the correct notes.
     */
    async reload() {
        await this.refreshOnce();
    },

    startPolling() {
        this.stopPolling();
        // Polling just reads from the WASM storage which is updated by the background indexer.
        this.refreshOnce().catch(() => {});
        this._timer = setInterval(() => {
            this.refreshOnce().catch(() => {});
        }, 5_000);
    },

    stopPolling() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    async refreshOnce() {
        if (this._refreshing) return;
        if (!App.state.wallet.connected || !App.state.wallet.address) return;

        this._refreshing = true;
        try {
            const LIMIT = 200;
            const address = App.state.wallet.address;
            const list = await getHandle().webClient.getUserNotes(address, LIMIT);
            const notes = Array.isArray(list) ? list : [];

            App.state.notes = notes.map(n => ({
                id: n.id,
                amount: n.amount,
                spent: !!n.spent,
                leafIndex: n.leafIndex ?? 0,
                createdAtLedger: n.createdAtLedger ?? 0,
                createdAtText: n.createdAtLedger ? `Ledger ${n.createdAtLedger}` : '',
            }));

            this.render();
        } catch (e) {
            console.warn('[NotesTable] refresh failed:', e);
            // Keep it quiet; indexer/retention can be flaky.
            Toast.show('Failed to refresh notes (will retry)', 'info');
        } finally {
            this._refreshing = false;
        }
    },
    
    render() {
        const tbody = document.getElementById('notes-tbody');
        const empty = document.getElementById('empty-notes');
        
        // Clear
        tbody.replaceChildren();
        
        // Filter and sort
        let notes = [...App.state.notes];
        if (this.filter === 'unspent') notes = notes.filter(n => !n.spent);
        if (this.filter === 'spent') notes = notes.filter(n => n.spent);
        notes.sort((a, b) => (b.leafIndex ?? 0) - (a.leafIndex ?? 0));
        
        if (notes.length === 0) {
            empty.classList.remove('hidden');
            empty.classList.add('flex');
            return;
        }
        
        empty.classList.add('hidden');
        empty.classList.remove('flex');
        
        notes.forEach(note => {
            tbody.appendChild(Templates.createNoteRow(note));
        });
    }
};

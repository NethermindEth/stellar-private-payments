/**
 * Notes Table - displays user notes with filtering and actions.
 * @module ui/notes-table
 */

import { getHandle } from '../wasm-facade.js';
import { App, Toast } from './core.js';
import { Templates } from './templates.js';

export const NotesTable = {
    filter: 'all',
    sortKey: null,
    sortDir: 'desc',
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
        
        // Sort buttons
        document.querySelectorAll('.sort-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.sort;
                if (this.sortKey === key) {
                    this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortKey = key;
                    this.sortDir = 'asc';
                }
                this._updateSortIcons();
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
            App.events.dispatchEvent(new CustomEvent('notes:updated'));
        } catch (e) {
            console.warn('[NotesTable] refresh failed:', e);
            // Keep it quiet; indexer/retention can be flaky.
            Toast.show('Failed to refresh notes (will retry)', 'info');
        } finally {
            this._refreshing = false;
        }
    },
    
    _updateSortIcons() {
        document.querySelectorAll('.sort-btn').forEach(btn => {
            const key = btn.dataset.sort;
            const icon = btn.querySelector('.sort-icon');
            if (this.sortKey === key) {
                btn.classList.add('text-brand-400');
                btn.classList.remove('text-dark-500');
                icon.classList.remove('opacity-50');
                icon.style.transform = this.sortDir === 'asc' ? 'rotate(0deg)' : 'rotate(180deg)';
            } else {
                btn.classList.remove('text-brand-400');
                btn.classList.add('text-dark-500');
                icon.classList.add('opacity-50');
                icon.style.transform = 'none';
            }
        });
    },

    _compareNotes(a, b) {
        const dir = this.sortDir === 'asc' ? 1 : -1;
        switch (this.sortKey) {
            case 'id':
                return dir * a.id.localeCompare(b.id);
            case 'amount':
                return dir * ((a.amount ?? 0) - (b.amount ?? 0));
            case 'created':
                return dir * ((a.createdAtLedger ?? 0) - (b.createdAtLedger ?? 0));
            case 'status':
                return dir * ((a.spent ? 1 : 0) - (b.spent ? 1 : 0));
            default:
                return 0;
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
        notes.sort((a, b) => this._compareNotes(a, b));
        
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

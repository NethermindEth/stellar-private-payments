import { client } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { Templates } from './templates.js';
import { filterNotes } from './notes-view.js';

const PAGE_SIZE = 20;

function noteWithLabels(note) {
    const pool = App.state.pools.find(item => item.poolContractId === note.poolContractId);
    return {
        ...note,
        tokenLabel: Utils.poolLabel(pool),
    };
}

export const NotesTable = {
    filter: 'all',
    page: 0,
    totalCount: 0,
    _timer: null,
    _refreshing: false,

    init() {
        document.querySelectorAll('[data-note-filter]').forEach(btn => {
            btn.addEventListener('click', () => {
                this.filter = btn.dataset.noteFilter;
                document.querySelectorAll('[data-note-filter]').forEach(item => {
                    const active = item === btn;
                    item.classList.toggle('bg-cyan-400/20', active);
                    item.classList.toggle('text-cyan-100', active);
                    item.classList.toggle('text-slate-400', !active);
                });
                this.page = 0;
                this.refreshOnce().catch(() => {});
            });
        });

        document.getElementById('advanced-notes-prev')?.addEventListener('click', () => {
            if (this.page > 0) {
                this.page--;
                this.refreshOnce().catch(() => {});
            }
        });

        document.getElementById('advanced-notes-next')?.addEventListener('click', () => {
            if ((this.page + 1) * PAGE_SIZE < this.totalCount) {
                this.page++;
                this.refreshOnce().catch(() => {});
            }
        });

        App.events.addEventListener('wallet:ready', () => this.startPolling());
        App.events.addEventListener('wallet:disconnected', () => {
            this.stopPolling();
            this.page = 0;
            this.totalCount = 0;
            App.state.notes = [];
            this.render();
        });
        App.events.addEventListener('pool:config', () => this.render());
        App.events.addEventListener('pool:selected', () => this.render());
    },

    startPolling() {
        this.stopPolling();
        this.refreshOnce().catch(() => {});
        this._timer = setInterval(() => this.refreshOnce().catch(() => {}), 8_000);
    },

    stopPolling() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    spentFilter() {
        return this.filter === 'unspent' ? false : this.filter === 'spent' ? true : null;
    },

    async refreshOnce() {
        if (this._refreshing || !App.state.wallet.address) return;
        this._refreshing = true;
        try {
            const address = App.state.wallet.address;
            const offset = this.page * PAGE_SIZE;
            const spent = this.spentFilter();
            const { notes: list, total: count } = await client().getUserNotes(address, offset, PAGE_SIZE, spent);
            this.totalCount = count ?? 0;
            App.state.notes = (Array.isArray(list) ? list : []).map(note => ({
                id: note.id,
                poolContractId: note.poolContractId,
                amount: note.amount,
                createdAtLedger: note.createdAtLedger,
                spent: !!note.spent,
            }));
            this.render();
            App.events.dispatchEvent(new CustomEvent('notes:updated'));
        } catch (error) {
            console.warn('[NotesTable] refresh failed:', error);
            Toast.show('Failed to refresh notes', 'info');
        } finally {
            this._refreshing = false;
        }
    },

    render() {
        const tbody = document.getElementById('advanced-notes-tbody');
        const empty = document.getElementById('advanced-notes-empty');
        const pagination = document.getElementById('advanced-notes-pagination');
        const prevBtn = document.getElementById('advanced-notes-prev');
        const nextBtn = document.getElementById('advanced-notes-next');
        const pageLabel = document.getElementById('advanced-notes-page');
        if (!tbody || !empty) return;

        tbody.replaceChildren();
        const filtered = filterNotes(App.state.notes, {
            status: this.filter,
            poolId: App.state.selectedPoolId,
        }).map(noteWithLabels);

        if (!filtered.length) {
            empty.classList.remove('hidden');
            pagination?.classList.add('hidden');
            pagination?.classList.remove('flex');
            return;
        }

        empty.classList.add('hidden');
        filtered.forEach(note => {
            tbody.appendChild(Templates.createNoteRow(note, {
                onUse: (selected) => App.events.dispatchEvent(new CustomEvent('advanced:use-note', { detail: selected })),
                onCopy: (selected) => Utils.copyToClipboard(selected.id),
            }));
        });

        const totalPages = Math.max(1, Math.ceil(this.totalCount / PAGE_SIZE));
        if (totalPages > 1) {
            pagination?.classList.remove('hidden');
            pagination?.classList.add('flex');
            if (prevBtn) prevBtn.disabled = this.page === 0;
            if (nextBtn) nextBtn.disabled = (this.page + 1) >= totalPages;
            if (pageLabel) pageLabel.textContent = `Page ${this.page + 1} of ${totalPages}`;
        } else {
            pagination?.classList.add('hidden');
            pagination?.classList.remove('flex');
        }
    },
};

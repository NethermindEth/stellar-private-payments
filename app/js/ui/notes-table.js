import { getHandle } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { Templates } from './templates.js';

function noteWithLabels(note) {
    const pool = App.state.pools.find(item => item.poolContractId === note.poolContractId);
    return {
        ...note,
        tokenLabel: Utils.poolLabel(pool),
    };
}

export const NotesTable = {
    filter: 'all',
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
                this.render();
            });
        });

        App.events.addEventListener('wallet:ready', () => this.startPolling());
        App.events.addEventListener('wallet:disconnected', () => {
            this.stopPolling();
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

    async refreshOnce() {
        if (this._refreshing || !App.state.wallet.address) return;
        this._refreshing = true;
        try {
            const list = await getHandle().webClient.getUserNotes(App.state.wallet.address, 200);
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
        if (!tbody || !empty) return;

        tbody.replaceChildren();
        const filtered = App.state.notes
            .filter(note => this.filter === 'all' ? true : this.filter === 'unspent' ? !note.spent : note.spent)
            .filter(note => !App.state.selectedPoolId || note.poolContractId === App.state.selectedPoolId)
            .map(noteWithLabels);

        if (!filtered.length) {
            empty.classList.remove('hidden');
            return;
        }

        empty.classList.add('hidden');
        filtered.forEach(note => {
            tbody.appendChild(Templates.createNoteRow(note, {
                onUse: (selected) => App.events.dispatchEvent(new CustomEvent('advanced:use-note', { detail: selected })),
                onCopy: (selected) => Utils.copyToClipboard(selected.id),
            }));
        });
    },
};

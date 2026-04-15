/**
 * Address Book UI - shows registered public keys for private transfers.
 *
 * Data source: WASM WebClient.getRecentPublicKeys().
 * No JS state/DB layer.
 */

import { getHandle } from '../wasm-facade.js';
import { App, Utils, Toast } from './core.js';

export const AddressBook = {
    _filterDebounceTimer: null,
    _cached: null,

    init() {
        document.querySelectorAll('.section-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switchSection(btn.dataset.sectionTab));
        });

        const searchInput = document.getElementById('addressbook-search');
        const searchBtn = document.getElementById('addressbook-search-btn');

        searchInput?.addEventListener('input', () => {
            this._debouncedFilter(searchInput.value.trim());
        });
        searchInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this._debouncedFilter(searchInput.value.trim());
        });
        searchBtn?.addEventListener('click', () => {
            this._debouncedFilter(searchInput?.value.trim());
        });

        document.getElementById('addressbook-refresh-btn')?.addEventListener('click', async () => {
            await this.refresh();
        });

        App.events.addEventListener('wallet:ready', () => {
            this._cached = null;
            this.render().catch(() => {});
        });
    },

    switchSection(section) {
        document.querySelectorAll('.section-tab-btn').forEach(btn => {
            const isActive = btn.dataset.sectionTab === section;
            btn.setAttribute('aria-selected', isActive);
            btn.classList.toggle('bg-dark-800', isActive);
            btn.classList.toggle('text-brand-500', isActive);
            btn.classList.toggle('border-brand-500/30', isActive);
            btn.classList.toggle('border', isActive);
            btn.classList.toggle('text-dark-400', !isActive);
        });

        document.querySelectorAll('.section-panel').forEach(panel => panel.classList.add('hidden'));
        document.getElementById(`section-panel-${section}`)?.classList.remove('hidden');

        if (section === 'addressbook') {
            this.render().catch(e => {
                console.error('[AddressBook] render failed:', e);
            });
        }
    },

    async refresh() {
        this._cached = null;
        await this.render();
        Toast.show('Address book refreshed', 'success');
    },

    _debouncedFilter(searchTerm) {
        if (this._filterDebounceTimer) clearTimeout(this._filterDebounceTimer);
        this._filterDebounceTimer = setTimeout(() => {
            this.filterTable(searchTerm);
        }, 150);
    },

    async _loadIfNeeded() {
        if (this._cached) return this._cached;
        if (!App.state.wallet.connected) return [];
        const list = await getHandle().webClient.getRecentPublicKeys(100);
        this._cached = Array.isArray(list) ? list : [];
        return this._cached;
    },

    async render() {
        const tbody = document.getElementById('addressbook-tbody');
        const empty = document.getElementById('empty-addressbook');
        const loading = document.getElementById('addressbook-loading');
        const searchResult = document.getElementById('addressbook-search-result');
        const searchInput = document.getElementById('addressbook-search');

        if (!tbody) return;

        loading?.classList.remove('hidden');
        empty?.classList.add('hidden');
        searchResult?.classList.add('hidden');
        tbody.replaceChildren();

        const registrations = await this._loadIfNeeded();
        const currentFilter = searchInput?.value.trim().toUpperCase() || '';
        const filtered = currentFilter
            ? registrations.filter(r => String(r.address || '').toUpperCase().startsWith(currentFilter))
            : registrations;

        loading?.classList.add('hidden');

        // Always show self entry (even if not registered) for easy copy/share.
        if (App.state.wallet.connected && App.state.wallet.address && App.state.keys.notePublicKey && App.state.keys.encryptionPublicKey) {
            tbody.appendChild(this._createRow({
                address: App.state.wallet.address,
                noteKey: App.state.keys.notePublicKey,
                encryptionKey: App.state.keys.encryptionPublicKey,
                ledger: 0,
                _self: true,
            }));
        }

        if (filtered.length === 0 && tbody.children.length === 0) {
            empty?.classList.remove('hidden');
            empty?.classList.add('flex');
            return;
        }

        empty?.classList.add('hidden');
        empty?.classList.remove('flex');

        filtered.forEach(record => {
            tbody.appendChild(this._createRow(record));
        });
    },

    async filterTable(searchTerm) {
        const tbody = document.getElementById('addressbook-tbody');
        const empty = document.getElementById('empty-addressbook');
        const searchResult = document.getElementById('addressbook-search-result');
        if (!tbody) return;

        searchResult?.classList.add('hidden');
        const registrations = await this._loadIfNeeded();

        const term = String(searchTerm || '').toUpperCase();
        const matches = term
            ? registrations.filter(r => String(r.address || '').toUpperCase().startsWith(term))
            : registrations;

        // Preserve self row if it exists as the first row.
        const existingSelfRow = tbody.querySelector('tr[data-self="true"]');
        tbody.replaceChildren();
        if (existingSelfRow) tbody.appendChild(existingSelfRow);

        if (matches.length === 0 && tbody.children.length === 0) {
            empty?.classList.remove('hidden');
            empty?.classList.add('flex');
            return;
        }

        empty?.classList.add('hidden');
        empty?.classList.remove('flex');

        matches.forEach(record => tbody.appendChild(this._createRow(record)));
    },

    _createRow(record) {
        const tpl = App.templates.addressBookRow;
        const row = tpl.content.cloneNode(true).firstElementChild;

        const address = record.address || '';
        const noteKey = record.noteKey || '';
        const encryptionKey = record.encryptionKey || '';
        const ledger = record.ledger;

        if (record._self) {
            row.dataset.self = 'true';
        }

        row.querySelector('.ab-address').textContent = Utils.truncateHex(address, 7, 6);
        row.querySelector('.ab-address').title = address;
        row.querySelector('.ab-notekey').textContent = Utils.truncateHex(String(noteKey), 10, 8);
        row.querySelector('.ab-notekey').title = String(noteKey);
        row.querySelector('.ab-enckey').textContent = Utils.truncateHex(String(encryptionKey), 10, 8);
        row.querySelector('.ab-enckey').title = String(encryptionKey);
        row.querySelector('.ab-date').textContent = record._self ? 'You' : (ledger ? `Ledger ${ledger}` : '');

        row.querySelector('.copy-address-btn')?.addEventListener('click', () => Utils.copyToClipboard(address));
        row.querySelector('.copy-notekey-btn')?.addEventListener('click', () => Utils.copyToClipboard(String(noteKey)));
        row.querySelector('.copy-enckey-btn')?.addEventListener('click', () => Utils.copyToClipboard(String(encryptionKey)));

        row.querySelector('.use-transfer-btn')?.addEventListener('click', () => {
            const nk = document.getElementById('transfer-recipient-key');
            const ek = document.getElementById('transfer-recipient-enc-key');
            if (nk) nk.value = String(noteKey);
            if (ek) ek.value = String(encryptionKey);
            document.getElementById('tab-transfer')?.click();
            Toast.show('Recipient keys filled from address book', 'success');
        });

        return row;
    },
};


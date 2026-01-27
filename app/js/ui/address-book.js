/**
 * Address Book UI - displays registered public keys and enables lookup for transfers.
 * @module ui/address-book
 */

import { StateManager } from '../state/index.js';
import { App, Utils, Toast } from './core.js';

// Forward reference to Tabs for switching to transfer
let TabsRef = null;

/**
 * Sets the Tabs reference for navigation.
 * @param {Object} tabs - The Tabs module
 */
export function setAddressBookTabsRef(tabs) {
    TabsRef = tabs;
}

export const AddressBook = {
    isInitialized: false,
    _filterDebounceTimer: null,
    _cachedRegistrations: null,
    
    init() {
        // Store template reference
        App.templates.addressBookRow = document.getElementById('tpl-addressbook-row');
        
        // Section tab switching
        document.querySelectorAll('.section-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switchSection(btn.dataset.sectionTab));
        });
        
        // Search functionality
        const searchInput = document.getElementById('addressbook-search');
        const searchBtn = document.getElementById('addressbook-search-btn');
        
        // Live filtering as user types (debounced)
        searchInput?.addEventListener('input', () => {
            this.debouncedFilter(searchInput.value.trim());
        });
        
        // Enter key for exact on-chain lookup (full address)
        searchInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.search(searchInput.value.trim());
            }
        });
        
        searchBtn?.addEventListener('click', () => {
            this.search(searchInput?.value.trim());
        });
        
        // Refresh button
        document.getElementById('addressbook-refresh-btn')?.addEventListener('click', async () => {
            const icon = document.getElementById('addressbook-refresh-icon');
            if (icon) {
                icon.classList.add('animate-spin');
            }
            try {
                this._cachedRegistrations = null;
                await this.render();
            } finally {
                if (icon) {
                    icon.classList.remove('animate-spin');
                }
            }
        });
        
        // Listen for new registrations
        StateManager.on('publicKeyRegistered', () => {
            this._cachedRegistrations = null;
            this.render();
        });
        
        this.isInitialized = true;
    },
    
    /**
     * Debounces the filter operation to avoid excessive updates while typing.
     * @param {string} searchTerm - Current search input value
     */
    debouncedFilter(searchTerm) {
        if (this._filterDebounceTimer) {
            clearTimeout(this._filterDebounceTimer);
        }
        this._filterDebounceTimer = setTimeout(() => {
            this.filterTable(searchTerm);
        }, 150);
    },
    
    /**
     * Filters the address book table in real-time without notifications.
     * Shows all entries when search is empty.
     * @param {string} searchTerm - Filter term (prefix match)
     */
    async filterTable(searchTerm) {
        const tbody = document.getElementById('addressbook-tbody');
        const empty = document.getElementById('empty-addressbook');
        const searchResult = document.getElementById('addressbook-search-result');
        
        if (!tbody) return;
        
        // Hide search result panel during filtering
        searchResult?.classList.add('hidden');
        
        // Get cached registrations or fetch them
        if (!this._cachedRegistrations) {
            try {
                this._cachedRegistrations = await StateManager.getRecentPublicKeys(100);
            } catch (error) {
                console.error('[AddressBook] Failed to load registrations:', error);
                return;
            }
        }
        
        const registrations = this._cachedRegistrations;
        
        // Filter by prefix if search term provided
        const term = searchTerm.toUpperCase();
        const matches = term 
            ? registrations.filter(r => r.address.toUpperCase().startsWith(term))
            : registrations;
        
        tbody.replaceChildren();
        
        if (matches.length === 0) {
            empty?.classList.remove('hidden');
            empty?.classList.add('flex');
            return;
        }
        
        empty?.classList.add('hidden');
        empty?.classList.remove('flex');
        
        matches.forEach(record => {
            tbody.appendChild(this.createRow(record));
        });
    },
    
    /**
     * Switches between notes and address book sections.
     * @param {string} section - 'notes' or 'addressbook'
     */
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
        
        document.querySelectorAll('.section-panel').forEach(panel => {
            panel.classList.add('hidden');
        });
        
        const targetPanel = document.getElementById(`section-panel-${section}`);
        if (targetPanel) {
            targetPanel.classList.remove('hidden');
        }
        
        // Render address book when switching to it
        if (section === 'addressbook') {
            this.render();
        }
    },
    
    /**
     * Renders the address book table with recent registrations.
     * Respects the current search filter if one is active.
     */
    async render() {
        const tbody = document.getElementById('addressbook-tbody');
        const empty = document.getElementById('empty-addressbook');
        const loading = document.getElementById('addressbook-loading');
        const searchResult = document.getElementById('addressbook-search-result');
        const searchInput = document.getElementById('addressbook-search');
        
        if (!tbody) return;
        
        // Show loading, hide others
        loading?.classList.remove('hidden');
        empty?.classList.add('hidden');
        searchResult?.classList.add('hidden');
        tbody.replaceChildren();
        
        try {
            const registrations = await StateManager.getRecentPublicKeys(100);
            this._cachedRegistrations = registrations;
            
            loading?.classList.add('hidden');
            
            // If there's an active search filter, apply it
            const currentFilter = searchInput?.value.trim().toUpperCase() || '';
            const filtered = currentFilter 
                ? registrations.filter(r => r.address.toUpperCase().startsWith(currentFilter))
                : registrations;
            
            if (filtered.length === 0) {
                empty?.classList.remove('hidden');
                empty?.classList.add('flex');
                return;
            }
            
            empty?.classList.add('hidden');
            empty?.classList.remove('flex');
            
            filtered.forEach(record => {
                tbody.appendChild(this.createRow(record));
            });
        } catch (error) {
            console.error('[AddressBook] Failed to load registrations:', error);
            loading?.classList.add('hidden');
            
            // Check if this is a database upgrade issue
            if (error.name === 'NotFoundError' || error.message?.includes('object stores was not found')) {
                this.renderDatabaseUpgradeError();
            } else {
                empty?.classList.remove('hidden');
            }
        }
    },
    
    /**
     * Renders a message when database needs upgrade (store not found).
     */
    renderDatabaseUpgradeError() {
        const container = document.getElementById('addressbook-search-result');
        if (!container) return;
        
        container.classList.remove('hidden');
        container.innerHTML = `
            <div class="p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-4 h-4 text-orange-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    <h4 class="text-sm font-semibold text-orange-400">Database Upgrade Required</h4>
                </div>
                <p class="text-xs text-dark-400 mb-3">
                    The address book feature requires a database upgrade. Please close all other tabs with this site and refresh.
                </p>
                <div class="flex gap-2">
                    <button type="button" class="refresh-page-btn px-3 py-1.5 bg-orange-500 hover:bg-orange-400 text-dark-950 text-xs font-semibold rounded transition-colors">
                        Refresh Page
                    </button>
                    <button type="button" class="force-reset-btn px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 text-xs rounded border border-red-500/30 transition-colors">
                        Force Reset (deletes data)
                    </button>
                </div>
                <p class="text-[10px] text-dark-600 mt-2">
                    Force reset will delete all local data. You'll need to sync again.
                </p>
            </div>
        `;
        
        container.querySelector('.refresh-page-btn')?.addEventListener('click', () => {
            window.location.reload();
        });
        
        container.querySelector('.force-reset-btn')?.addEventListener('click', async () => {
            if (confirm('This will delete all local data including notes. You will need to sync again. Continue?')) {
                try {
                    await StateManager.forceResetDatabase();
                    Toast.show('Database reset. Refreshing...', 'success');
                    setTimeout(() => window.location.reload(), 1000);
                } catch (e) {
                    console.error('[AddressBook] Force reset failed:', e);
                    Toast.show('Reset failed: ' + e.message, 'error');
                }
            }
        });
    },
    
    /**
     * Searches for public keys by address prefix or full address.
     * For full 56-char addresses starting with G, performs on-chain lookup.
     * For partial input, filters the local table.
     * @param {string} searchTerm - Full Stellar address or prefix to search
     */
    async search(searchTerm) {
        // If empty, just show all results
        if (!searchTerm) {
            await this.render();
            return;
        }
        
        // Normalize to uppercase for consistent matching
        const term = searchTerm.toUpperCase();
        
        const searchResult = document.getElementById('addressbook-search-result');
        const tbody = document.getElementById('addressbook-tbody');
        const empty = document.getElementById('empty-addressbook');
        const loading = document.getElementById('addressbook-loading');
        
        // If it's a full valid address, do exact on-chain lookup
        if (term.startsWith('G') && term.length === 56) {
            loading?.classList.remove('hidden');
            empty?.classList.add('hidden');
            searchResult?.classList.add('hidden');
            tbody?.replaceChildren();
            
            try {
                const result = await StateManager.searchPublicKey(term);
                loading?.classList.add('hidden');
                
                if (result.found) {
                    searchResult?.classList.remove('hidden');
                    this.renderSearchResult(result.record, result.source);
                    Toast.show(`Found public key (${result.source})`, 'success');
                } else {
                    searchResult?.classList.remove('hidden');
                    this.renderSearchNotFound(term);
                }
            } catch (error) {
                console.error('[AddressBook] Search failed:', error);
                loading?.classList.add('hidden');
                Toast.show('Search failed: ' + error.message, 'error');
            }
            return;
        }
        
        // For partial search, use the live filter
        await this.filterTable(searchTerm);
    },
    
    /**
     * Renders a search result showing both encryption and note keys.
     * @param {Object} record - Public key record
     * @param {string} source - 'local' or 'onchain'
     */
    renderSearchResult(record, source) {
        const container = document.getElementById('addressbook-search-result');
        if (!container) return;
        
        const sourceLabel = source === 'onchain' ? 'Found on-chain' : 'Found locally';
        const sourceBadgeClass = source === 'onchain' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-brand-500/20 text-brand-400';
        
        // Use new fields if available, fallback to legacy publicKey
        const encryptionKey = record.encryptionKey || record.publicKey;
        const noteKey = record.noteKey || record.publicKey;
        
        container.innerHTML = `
            <div class="p-4 bg-dark-800 border border-dark-700 rounded-lg">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-dark-200">Search Result</h4>
                    <span class="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide rounded ${sourceBadgeClass}">${sourceLabel}</span>
                </div>
                <dl class="space-y-2 text-xs">
                    <div class="flex justify-between items-start">
                        <dt class="text-dark-500">Address</dt>
                        <dd class="font-mono text-dark-300 text-right break-all max-w-[300px]">${record.address}</dd>
                    </div>
                    <div class="flex justify-between items-start">
                        <dt class="text-dark-500">Encryption Key <span class="text-dark-600">(X25519)</span></dt>
                        <dd class="font-mono text-brand-400 text-right break-all max-w-[300px]">${Utils.truncateHex(encryptionKey, 12, 12)}</dd>
                    </div>
                    <div class="flex justify-between items-start">
                        <dt class="text-dark-500">Note Key <span class="text-dark-600">(BN254)</span></dt>
                        <dd class="font-mono text-emerald-400 text-right break-all max-w-[300px]">${Utils.truncateHex(noteKey, 12, 12)}</dd>
                    </div>
                </dl>
                <div class="flex gap-2 mt-4">
                    <button type="button" class="search-use-transfer flex-1 px-3 py-2 bg-brand-500 hover:bg-brand-400 text-dark-950 text-xs font-semibold rounded transition-colors">
                        Use in Transfer
                    </button>
                    <button type="button" class="search-copy-keys px-3 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-dark-300 text-xs rounded transition-colors">
                        Copy Keys
                    </button>
                    <button type="button" class="search-clear px-3 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-dark-400 text-xs rounded transition-colors">
                        Clear
                    </button>
                </div>
            </div>
        `;
        
        // Attach event listeners - pass both keys to transfer
        container.querySelector('.search-use-transfer')?.addEventListener('click', () => {
            this.useInTransfer(encryptionKey, noteKey);
        });
        
        container.querySelector('.search-copy-keys')?.addEventListener('click', () => {
            Utils.copyToClipboard(`Encryption: ${encryptionKey}\\nNote: ${noteKey}`);
        });
        
        container.querySelector('.search-clear')?.addEventListener('click', () => {
            container.classList.add('hidden');
            document.getElementById('addressbook-search').value = '';
            this.render();
        });
    },
    
    /**
     * Renders a not-found search result.
     * @param {string} address - The searched address
     */
    renderSearchNotFound(address) {
        const container = document.getElementById('addressbook-search-result');
        if (!container) return;
        
        container.innerHTML = `
            <div class="p-4 bg-dark-800 border border-red-500/30 rounded-lg">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-4 h-4 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="15" y1="9" x2="9" y2="15"/>
                        <line x1="9" y1="9" x2="15" y2="15"/>
                    </svg>
                    <h4 class="text-sm font-semibold text-red-400">Not Found</h4>
                </div>
                <p class="text-xs text-dark-400 mb-3">
                    No registered public key found for <span class="font-mono text-dark-300">${Utils.truncateHex(address, 8, 8)}</span>
                </p>
                <p class="text-xs text-dark-500">
                    The user may not have registered their public key yet. Ask them to register via the wallet menu.
                </p>
                <button type="button" class="search-clear mt-3 px-3 py-1.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-dark-400 text-xs rounded transition-colors">
                    Clear Search
                </button>
            </div>
        `;
        
        container.querySelector('.search-clear')?.addEventListener('click', () => {
            container.classList.add('hidden');
            document.getElementById('addressbook-search').value = '';
            this.render();
        });
    },
    
    /**
     * Creates a table row for an address book entry.
     * @param {Object} record - Public key record
     * @returns {HTMLElement}
     */
    createRow(record) {
        const row = App.templates.addressBookRow.content.cloneNode(true).firstElementChild;
        row.dataset.address = record.address;
        
        // Use new fields if available, fallback to legacy publicKey
        const encryptionKey = record.encryptionKey || record.publicKey;
        const noteKey = record.noteKey || record.publicKey;
        
        row.querySelector('.ab-address').textContent = Utils.truncateHex(record.address, 8, 8);
        row.querySelector('.ab-notekey').textContent = Utils.truncateHex(noteKey, 8, 6);
        row.querySelector('.ab-enckey').textContent = Utils.truncateHex(encryptionKey, 8, 6);
        row.querySelector('.ab-date').textContent = record.registeredAt 
            ? Utils.formatDate(record.registeredAt)
            : `Ledger ${record.ledger}`;
        
        // Use in transfer button - pass both keys
        row.querySelector('.use-transfer-btn')?.addEventListener('click', () => {
            this.useInTransfer(encryptionKey, noteKey);
        });
        
        // Copy note key button
        row.querySelector('.copy-notekey-btn')?.addEventListener('click', () => {
            Utils.copyToClipboard(noteKey);
            Toast.show('Note key copied', 'success');
        });
        
        // Copy encryption key button
        row.querySelector('.copy-enckey-btn')?.addEventListener('click', () => {
            Utils.copyToClipboard(encryptionKey);
            Toast.show('Encryption key copied', 'success');
        });
        
        // Copy address button
        row.querySelector('.copy-address-btn')?.addEventListener('click', () => {
            Utils.copyToClipboard(record.address);
            Toast.show('Address copied', 'success');
        });
        
        return row;
    },
    
    /**
     * Fills recipient fields in transfer or transact mode.
     * If in transact mode, stays there and fills the first empty output.
     * If first output has keys filled, tries the second output.
     * If in transfer mode (or any other), switches to transfer tab.
     * @param {string} encryptionKey - X25519 encryption public key
     * @param {string} noteKey - BN254 note public key
     */
    useInTransfer(encryptionKey, noteKey) {
        // Check if we're in transact mode
        if (App.state.activeTab === 'transact') {
            this.fillTransactOutput(encryptionKey, noteKey);
            return;
        }
        
        // Default: fill transfer fields and switch to transfer tab
        const noteKeyInput = document.getElementById('transfer-recipient-key');
        if (noteKeyInput) {
            noteKeyInput.value = noteKey;
            noteKeyInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        
        const encKeyInput = document.getElementById('transfer-recipient-enc-key');
        if (encKeyInput) {
            encKeyInput.value = encryptionKey;
            encKeyInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        
        if (TabsRef) {
            TabsRef.switch('transfer');
        }
        
        Toast.show('Keys added to transfer', 'success');
    },
    
    /**
     * Fills transact mode output fields with recipient keys.
     * Finds the first output with empty keys, or the second if first is filled.
     * @param {string} encryptionKey - X25519 encryption public key
     * @param {string} noteKey - BN254 note public key
     */
    fillTransactOutput(encryptionKey, noteKey) {
        const outputs = document.querySelectorAll('#transact-outputs .advanced-output-row');
        if (!outputs.length) {
            Toast.show('No output rows found', 'error');
            return;
        }
        
        // Find the first output with empty keys
        let targetRow = null;
        for (const row of outputs) {
            const noteKeyInput = row.querySelector('.output-note-key');
            const encKeyInput = row.querySelector('.output-enc-key');
            
            const noteKeyEmpty = !noteKeyInput?.value.trim();
            const encKeyEmpty = !encKeyInput?.value.trim();
            
            if (noteKeyEmpty && encKeyEmpty) {
                targetRow = row;
                break;
            }
        }
        
        // If no completely empty output found, try to find one with at least one empty key
        if (!targetRow) {
            for (const row of outputs) {
                const noteKeyInput = row.querySelector('.output-note-key');
                const encKeyInput = row.querySelector('.output-enc-key');
                
                const noteKeyEmpty = !noteKeyInput?.value.trim();
                const encKeyEmpty = !encKeyInput?.value.trim();
                
                if (noteKeyEmpty || encKeyEmpty) {
                    targetRow = row;
                    break;
                }
            }
        }
        
        if (!targetRow) {
            Toast.show('All outputs already have recipients', 'info');
            return;
        }
        
        const noteKeyInput = targetRow.querySelector('.output-note-key');
        const encKeyInput = targetRow.querySelector('.output-enc-key');
        
        if (noteKeyInput) {
            noteKeyInput.value = noteKey;
            noteKeyInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        
        if (encKeyInput) {
            encKeyInput.value = encryptionKey;
            encKeyInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        
        this.switchSection('notes');
        
        const outputIndex = parseInt(targetRow.dataset.index || '0', 10) + 1;
        Toast.show(`Keys added to output ${outputIndex}`, 'success');
    }
};

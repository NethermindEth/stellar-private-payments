/**
 * Contract Reader - reads and displays on-chain contract state.
 * @module ui/contract-reader
 */

import { 
    readAllContractStates, 
    getPoolEvents, 
    formatAddress, 
    getDeployedContracts 
} from '../stellar.js';

// Forward reference to SyncUI - set by main init
let SyncUIRef = null;

/**
 * Sets the SyncUI reference for force resync button.
 * @param {Object} syncUI
 */
export function setSyncUIRef(syncUI) {
    SyncUIRef = syncUI;
}

export const PoolEventsFetcher = {
    isLoading: false,
    events: [],
    maxEvents: 3,
    refreshIntervalId: null,
    
    init() {
        this.refresh();
        this.refreshIntervalId = setInterval(() => this.refresh(), 30000);
    },

    destroy() {
        if (this.refreshIntervalId) {
            clearInterval(this.refreshIntervalId);
            this.refreshIntervalId = null;
        }
    },

    async refresh() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        this.showLoading();
        
        try {
            const result = await getPoolEvents(this.maxEvents);
            
            if (result.success && result.events.length > 0) {
                this.events = result.events.slice(0, this.maxEvents);
                this.displayEvents();
                this.setStatus('success');
            } else if (result.success) {
                this.events = [];
                this.showEmpty();
                this.setStatus('success', 'No events');
            } else {
                this.setStatus('error', result.error || 'Failed');
                this.showEmpty();
            }
        } catch (err) {
            console.error('[PoolEventsFetcher] Error:', err);
            this.setStatus('error', 'Error');
            this.showEmpty();
        } finally {
            this.isLoading = false;
        }
    },
    
    displayEvents() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        
        loadingEl.classList.add('hidden');
        
        if (!this.events.length) {
            this.showEmpty();
            return;
        }
        
        emptyEl.classList.add('hidden');
        container.innerHTML = '';
        
        // Group events by ledger
        const byLedger = new Map();
        for (const event of this.events) {
            const ledger = event.ledger;
            if (!byLedger.has(ledger)) {
                byLedger.set(ledger, { ledger, nullifiers: 0, commitments: 0, events: [], txHash: event.txHash });
            }
            const group = byLedger.get(ledger);
            group.events.push(event);
            
            const topic = event.topic?.[0] || '';
            if (topic.includes('nullif')) group.nullifiers++;
            if (topic.includes('commit')) group.commitments++;
        }
        
        const groups = Array.from(byLedger.values()).slice(0, this.maxEvents);
        
        for (const group of groups) {
            // Determine transaction type based on event patterns
            let txType = 'Pool Activity';
            let txIcon = '';
            
            if (group.nullifiers === 0 && group.commitments > 0) {
                txType = 'Deposit';
                txIcon = '<svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m0 0l-4-4m4 4l4-4"/></svg>';
            } else if (group.nullifiers > 0 && group.commitments === 0) {
                txType = 'Withdraw';
                txIcon = '<svg class="w-3.5 h-3.5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 20V4m0 0l-4 4m4-4l4 4"/></svg>';
            } else if (group.nullifiers > 0 && group.commitments > 0) {
                txType = 'Transfer';
                txIcon = '<svg class="w-3.5 h-3.5 text-brand-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m-12 6h12m-12 6h12M4 7h.01M4 13h.01M4 19h.01"/></svg>';
            }
            
            // Create list item with link to Stellar Expert
            const li = document.createElement('li');
            li.className = 'flex justify-between items-center p-2 bg-dark-800 rounded text-xs hover:bg-dark-700 transition-colors';
            
            const leftDiv = document.createElement('div');
            leftDiv.className = 'flex items-center gap-2';
            leftDiv.innerHTML = txIcon;
            
            const txInfo = document.createElement('div');
            txInfo.className = 'flex flex-col';
            
            const txTypeSpan = document.createElement('span');
            txTypeSpan.className = 'text-dark-200 font-medium';
            txTypeSpan.textContent = txType;
            
            const txDetails = document.createElement('span');
            txDetails.className = 'text-[10px] text-dark-500';
            txDetails.textContent = `${group.commitments} commit${group.commitments !== 1 ? 's' : ''}, ${group.nullifiers} nullifier${group.nullifiers !== 1 ? 's' : ''}`;
            
            txInfo.appendChild(txTypeSpan);
            txInfo.appendChild(txDetails);
            leftDiv.appendChild(txInfo);
            
            const ledgerLink = document.createElement('a');
            ledgerLink.href = `https://stellar.expert/explorer/testnet/ledger/${group.ledger}`;
            ledgerLink.target = '_blank';
            ledgerLink.rel = 'noopener noreferrer';
            ledgerLink.className = 'text-dark-400 hover:text-brand-400 transition-colors flex items-center gap-1';
            ledgerLink.innerHTML = `L${group.ledger} <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>`;
            ledgerLink.title = `View ledger ${group.ledger} on Stellar Expert`;
            
            li.appendChild(leftDiv);
            li.appendChild(ledgerLink);
            container.appendChild(li);
        }
    },
    
    showEmpty() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        
        container.innerHTML = '';
        loadingEl.classList.add('hidden');
        emptyEl.classList.remove('hidden');
    },
    
    showLoading() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        
        container.innerHTML = '';
        emptyEl.classList.add('hidden');
        loadingEl.classList.remove('hidden');
    },
    
    setStatus(status, text = '') {
        const el = document.getElementById('recent-tx-status');
        if (!el) return;
        
        switch (status) {
            case 'success':
                el.textContent = text || 'Updated';
                el.className = 'text-[10px] text-emerald-500';
                break;
            case 'error':
                el.textContent = text || 'Error';
                el.className = 'text-[10px] text-red-500';
                break;
            default:
                el.textContent = '—';
                el.className = 'text-[10px] text-dark-500';
        }
    },
    
    formatEventHash(event) {
        const topic = event.topic?.[0] || '';
        const prefix = typeof topic === 'string' ? topic.slice(0, 10) : 'Event';
        
        if (event.id) {
            const parts = event.id.split('-');
            const shortId = parts.length > 1 ? parts[1].slice(0, 6) : event.id.slice(0, 8);
            return `${prefix}...${shortId}`;
        }
        return `${prefix}...`;
    },
    
    formatEventTime(event) {
        if (event.ledger) {
            return `L${event.ledger}`;
        }
        return '--';
    }
};

export const ContractReader = {
    isLoading: false,
    lastUpdate: null,
    refreshIntervalId: null,
    errorCount: 0,

    init() {
        const refreshBtn = document.getElementById('btn-refresh-state');
        refreshBtn.addEventListener('click', () => this.refreshAll());
        
        const scanNotesBtn = document.getElementById('btn-scan-notes');
        if (scanNotesBtn && SyncUIRef) {
            scanNotesBtn.addEventListener('click', () => SyncUIRef.scanForNotes());
        }
        
        const forceResyncBtn = document.getElementById('btn-force-resync');
        if (forceResyncBtn && SyncUIRef) {
            forceResyncBtn.addEventListener('click', () => SyncUIRef.forceResync());
        }

        this.setAddresses();
        document.getElementById('network-name').textContent = 'Testnet';
        document.getElementById('chain-network-badge').textContent = 'Testnet';

        this.refreshAll();
        this.refreshIntervalId = setInterval(() => this.refreshAll(), 30000);
    },

    destroy() {
        if (this.refreshIntervalId) {
            clearInterval(this.refreshIntervalId);
            this.refreshIntervalId = null;
        }
    },
    
    setAddresses() {
        const contracts = getDeployedContracts();
        if (!contracts) {
            console.warn('[ContractReader] Deployed contracts not loaded yet');
            return;
        }
        
        // Helper to create Stellar Expert link
        const createExplorerLink = (contractId, displayText) => {
            const link = document.createElement('a');
            link.href = `https://stellar.expert/explorer/testnet/contract/${contractId}`;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.textContent = displayText;
            link.title = `View ${contractId} on Stellar Expert`;
            link.className = 'hover:text-brand-400 transition-colors';
            return link;
        };
        
        const poolEl = document.getElementById('pool-address');
        poolEl.textContent = '';
        poolEl.appendChild(createExplorerLink(contracts.pool, formatAddress(contracts.pool, 4, 4)));
        
        const membershipEl = document.getElementById('membership-address');
        membershipEl.textContent = '';
        membershipEl.appendChild(createExplorerLink(contracts.aspMembership, formatAddress(contracts.aspMembership, 4, 4)));
        
        const nonMembershipEl = document.getElementById('nonmembership-address');
        nonMembershipEl.textContent = '';
        nonMembershipEl.appendChild(createExplorerLink(contracts.aspNonMembership, formatAddress(contracts.aspNonMembership, 4, 4)));
    },
    
    async refreshAll() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        const refreshBtn = document.getElementById('btn-refresh-state');
        const refreshIcon = refreshBtn.querySelector('.refresh-icon');
        const errorDisplay = document.getElementById('contract-error-display');
        
        refreshIcon.classList.add('animate-spin');
        errorDisplay.classList.add('hidden');
        
        this.setStatus('pool-status', 'loading');
        this.setStatus('membership-status', 'loading');
        this.setStatus('nonmembership-status', 'loading');
        
        try {
            const result = await readAllContractStates();
            
            if (result.success) {
                this.displayPoolState(result.pool);
                this.displayMembershipState(result.aspMembership);
                this.displayNonMembershipState(result.aspNonMembership);
                
                this.lastUpdate = new Date();
                document.getElementById('state-last-updated').textContent = 
                    `Last updated: ${this.lastUpdate.toLocaleTimeString()}`;
                this.errorCount = 0;
            } else {
                this.displayError(result.error);
            }
        } catch (err) {
            console.error('[ContractReader] Error:', err);
            this.displayError(err.message);

            this.errorCount++;
            if (this.errorCount >= 5) {
                console.warn('[ContractReader] Too many failures, stopping auto-refresh');
                this.destroy();
            }
        } finally {
            this.isLoading = false;
            refreshIcon.classList.remove('animate-spin');
        }
    },
    
    displayPoolState(state) {
        if (!state || !state.success) {
            this.setStatus('pool-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('pool-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('pool-root');
        if (state.merkleRoot) {
            rootEl.textContent = this.truncateHash(state.merkleRoot);
            rootEl.title = state.merkleRoot;
        } else {
            rootEl.textContent = '—';
        }
        
        const commitmentsEl = document.getElementById('pool-commitments');
        if (state.totalCommitments !== undefined) {
            commitmentsEl.textContent = state.totalCommitments.toLocaleString();
        } else if (state.merkleNextIndex !== undefined) {
            commitmentsEl.textContent = state.merkleNextIndex.toLocaleString();
        } else {
            commitmentsEl.textContent = '0';
        }
        
        const levelsEl = document.getElementById('pool-levels');
        levelsEl.textContent = state.merkleLevels !== undefined ? state.merkleLevels : '—';
        
        const totalEl = document.getElementById('pool-total-value');
        if (totalEl) {
            totalEl.textContent = (state.totalCommitments || state.merkleNextIndex || 0).toLocaleString();
        }
    },
    
    displayMembershipState(state) {
        if (!state || !state.success) {
            this.setStatus('membership-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('membership-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('membership-root');
        if (state.root) {
            rootEl.textContent = this.truncateHash(state.root);
            rootEl.title = state.root;
        } else {
            rootEl.textContent = '—';
        }
        
        const countEl = document.getElementById('membership-count');
        if (state.nextIndex !== undefined) {
            countEl.textContent = `${state.nextIndex}${state.capacity ? ` / ${state.capacity.toLocaleString()}` : ''}`;
        } else {
            countEl.textContent = '0';
        }
    },
    
    displayNonMembershipState(state) {
        if (!state || !state.success) {
            this.setStatus('nonmembership-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('nonmembership-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('nonmembership-root');
        if (state.root) {
            rootEl.textContent = this.truncateHash(state.root);
            rootEl.title = state.root;
        } else {
            rootEl.textContent = '0x0...0';
        }
        
        const statusEl = document.getElementById('nonmembership-tree-status');
        if (state.isEmpty) {
            statusEl.textContent = 'Empty tree';
            statusEl.className = 'text-dark-500';
        } else {
            statusEl.textContent = 'Has entries';
            statusEl.className = 'text-emerald-400';
        }
    },
    
    displayError(message) {
        const errorDisplay = document.getElementById('contract-error-display');
        document.getElementById('contract-error-text').textContent = message || 'Failed to read contract state';
        errorDisplay.classList.remove('hidden');
    },
    
    setStatus(elementId, status, text = '') {
        const el = document.getElementById(elementId);
        if (!el) return;
        
        const indicatorId = elementId.replace('-status', '-indicator');
        const indicator = document.getElementById(indicatorId);
        
        switch (status) {
            case 'loading':
                el.textContent = 'Loading...';
                el.className = 'text-[10px] text-dark-400 animate-pulse';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-dark-400 animate-pulse';
                }
                break;
            case 'success':
                el.textContent = text || 'OK';
                el.className = 'text-[10px] text-emerald-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-emerald-500';
                }
                break;
            case 'error':
                el.textContent = text || 'Error';
                el.className = 'text-[10px] text-red-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-red-500';
                }
                break;
            default:
                el.textContent = text || '—';
                el.className = 'text-[10px] text-dark-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-dark-500';
                }
        }
    },
    
    truncateHash(hash) {
        if (!hash) return '—';
        if (typeof hash !== 'string') hash = String(hash);
        if (hash.length <= 16) return hash;
        if (hash.startsWith('0x')) {
            return hash.slice(0, 8) + '...' + hash.slice(-6);
        }
        return hash.slice(0, 6) + '...' + hash.slice(-6);
    }
};

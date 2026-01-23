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
        const template = document.getElementById('tpl-tx-item');
        
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
                byLedger.set(ledger, { ledger, nullifiers: 0, commitments: 0, events: [] });
            }
            const group = byLedger.get(ledger);
            group.events.push(event);
            
            const topic = event.topic?.[0] || '';
            if (topic.includes('nullif')) group.nullifiers++;
            if (topic.includes('commit')) group.commitments++;
        }
        
        const groups = Array.from(byLedger.values()).slice(0, this.maxEvents);
        
        for (const group of groups) {
            const clone = template.content.cloneNode(true);
            const li = clone.querySelector('li');
            
            let txType = 'Transaction';
            if (group.nullifiers === 2 && group.commitments === 2) {
                txType = 'Pool Activity';
            } else if (group.commitments > 0) {
                txType = `+${group.commitments} notes`;
            }
            
            li.querySelector('.tx-hash').textContent = txType;
            li.querySelector('.tx-hash').title = `Ledger ${group.ledger}: ${group.nullifiers} nullifiers, ${group.commitments} commitments`;
            li.querySelector('.tx-time').textContent = `L${group.ledger}`;
            
            container.appendChild(clone);
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
        
        document.getElementById('pool-address').textContent = formatAddress(contracts.pool, 4, 4);
        document.getElementById('pool-address').title = contracts.pool;
        
        document.getElementById('membership-address').textContent = formatAddress(contracts.aspMembership, 4, 4);
        document.getElementById('membership-address').title = contracts.aspMembership;
        
        document.getElementById('nonmembership-address').textContent = formatAddress(contracts.aspNonMembership, 4, 4);
        document.getElementById('nonmembership-address').title = contracts.aspNonMembership;
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

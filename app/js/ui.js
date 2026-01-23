/**
 * PoolStellar Compliant Private System
 * Main UI entry point - imports and initializes all UI modules.
 * 
 * @module ui
 */

import { loadDeployedContracts } from './stellar.js';
import { StateManager } from './state/index.js';

// Import UI modules
import {
    Storage,
    Templates,
    Tabs,
    Wallet,
    NotesTable,
    Deposit,
    Withdraw,
    Transfer,
    Transact,
    PoolEventsFetcher,
    ContractReader,
    ProverUI,
    SyncUI,
    setSyncUIRef,
    setDepositNotesTableRef,
    setWithdrawNotesTableRef,
    setTransactNotesTableRef,
    setTransferNotesTableRef,
} from './ui/index.js';

// Wire up cross-module references
setSyncUIRef(SyncUI);
setDepositNotesTableRef(NotesTable);
setWithdrawNotesTableRef(NotesTable);
setTransactNotesTableRef(NotesTable);
setTransferNotesTableRef(NotesTable);

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize core UI components
    Templates.init();
    Storage.load();
    
    // Initialize navigation and wallet
    Tabs.init();
    Wallet.init();
    
    // Initialize transaction forms
    Deposit.init();
    Withdraw.init();
    Transfer.init();
    Transact.init();
    NotesTable.init();
    
    // Load deployment config before initializing contract readers
    try {
        await loadDeployedContracts();
        ContractReader.init();
        PoolEventsFetcher.init();
        
        // Initialize state management and start sync
        SyncUI.init();
        await StateManager.initialize();
        
        // Check sync gap and show warning if needed
        await SyncUI.checkGap();
        
        // Start background sync
        SyncUI.startSync();
    } catch (err) {
        console.error('[Init] Failed to load deployment config:', err);
        const errorText = document.getElementById('contract-error-text');
        const errorDisplay = document.getElementById('contract-error-display');
        if (errorText && errorDisplay) {
            errorText.textContent = `Failed to load contract config: ${err.message}`;
            errorDisplay.classList.remove('hidden');
        }
    }
    
    // Initialize ZK prover in background
    ProverUI.initialize().catch(err => {
        console.warn('[Init] Background prover init failed (will retry on demand):', err.message);
    });
    
    console.log('PoolStellar initialized');
});

// Re-exports
export {
    Storage,
    Templates,
    Tabs,
    Wallet,
    NotesTable,
    Deposit,
    Withdraw,
    Transfer,
    Transact,
    PoolEventsFetcher,
    ContractReader,
    ProverUI,
    SyncUI,
};

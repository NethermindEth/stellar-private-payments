/**
 * PoolStellar Private Payment System
 * Main UI entry point - imports and initializes all UI modules.
 * 
 * @module ui
 */
import { Templates } from './ui/templates.js';
import { Tabs, Wallet } from './ui/navigation.js';
import { NotesTable } from './ui/notes-table.js';
import { AddressBook } from './ui/address-book.js';
import { Transactions } from './ui/transactions.js';
import { OnchainState } from './ui/onchain-state.js';
import { PoolEvents } from './ui/pool-events.js';

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
    Templates.init();
    Tabs.init();
    Wallet.init();
    Transactions.init();
    NotesTable.init();
    AddressBook.init();
    OnchainState.init();
    PoolEvents.init();
    
    // On first page load, attempt to onboard immediately (Freighter + WASM + keys).
    // If the user rejects, they can click "Connect Freighter" to retry.
    Wallet.connect({ auto: true }).catch(() => {});
});

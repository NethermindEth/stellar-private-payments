/**
 * UI Module Index - exports all UI modules.
 * @module ui
 */

export { App, Utils, Storage, Toast, deriveKeysFromWallet } from './core.js';
export { Templates, setTabsRef } from './templates.js';
export { getTransactionErrorMessage, getFriendlyErrorMessage, getErrorMessage } from './errors.js';
export { Tabs, Wallet, onWalletConnect, onWalletDisconnect, onAccountChange } from './navigation.js';
export { NotesTable } from './notes-table.js';
export { AddressBook, setAddressBookTabsRef } from './address-book.js';
export { PoolEventsFetcher, ContractReader, setSyncUIRef } from './contract-reader.js';
export { ProverUI } from './prover-ui.js';
export { SyncUI } from './sync-ui.js';
export {
    Deposit,
    Withdraw,
    Transact,
    Transfer,
    setDepositNotesTableRef,
    setWithdrawNotesTableRef,
    setTransactNotesTableRef,
    setTransferNotesTableRef,
} from './transactions/index.js';

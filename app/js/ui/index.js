/**
 * UI module barrel — optional re-exports for tooling/docs.
 * The main app entry (`ui.js`) imports modules directly.
 * @module ui
 */

export { App, Utils, Storage, Toast } from './core.js';
export { Templates } from './templates.js';
export { getTransactionErrorMessage, getFriendlyErrorMessage, getErrorMessage } from './errors.js';
export { Shell, Wallet } from './navigation.js';
export { NotesTable } from './notes-table.js';
export { AddressBook } from './address-book.js';
export { Transactions } from './transactions.js';
export { Dashboard } from './dashboard.js';

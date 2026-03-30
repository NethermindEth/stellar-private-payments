/**
 * IndexedDB wrapper — STUBBED OUT.
 *
 * All storage has been migrated to the Rust WASM StateManager (SQLite).
 * These exports exist only for backward compatibility with any code that
 * may still reference db.js. All operations are no-ops.
 *
 * @module state/db
 * @deprecated Use WASM StateManager via ./wasm.js instead
 */

const DB_NAME = 'poolstellar';
const DB_VERSION = 5;
const STORES = {};

export async function init() {
    console.warn('[DB] db.js is stubbed — storage is handled by WASM StateManager');
}
export async function get() { return undefined; }
export async function getAll() { return []; }
export async function getAllByIndex() { return []; }
export async function getByIndex() { return undefined; }
export async function count() { return 0; }
export async function put() { return undefined; }
export async function putAll() {}
export async function del() {}
export async function clear() {}
export async function clearAll() {}
export async function iterate() {}
export async function batch() {}
export async function deleteDatabase() {}
export async function forceReset() { await init(); }
export function close() {}

export { DB_NAME, DB_VERSION, STORES };

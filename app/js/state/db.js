/**
 * IndexedDB wrapper for PoolStellar state management.
 * Uses native IndexedDB API with promise wrappers.
 * @module state/db
 */

const DB_NAME = 'poolstellar';
const DB_VERSION = 2;

/**
 * Store configuration for IndexedDB schema.
 * @type {Object.<string, {keyPath: string, indexes?: Array<{name: string, keyPath: string, unique?: boolean}>}>}
 */
const STORES = {
    retention_config: { keyPath: 'rpcEndpoint' },
    sync_metadata: { keyPath: 'network' },
    pool_leaves: {
        keyPath: 'index',
        indexes: [{ name: 'by_commitment', keyPath: 'commitment', unique: true }]
    },
    pool_nullifiers: { keyPath: 'nullifier' },
    pool_encrypted_outputs: {
        keyPath: 'commitment',
        indexes: [{ name: 'by_ledger', keyPath: 'ledger' }]
    },
    asp_membership_leaves: {
        keyPath: 'index',
        indexes: [{ name: 'by_leaf', keyPath: 'leaf', unique: true }]
    },
    user_notes: {
        keyPath: 'id',
        indexes: [{ name: 'by_spent', keyPath: 'spent' }]
    }
};

let dbInstance = null;

/**
 * Opens the IndexedDB database, creating stores if needed.
 * @returns {Promise<IDBDatabase>}
 */
function openDatabase() {
    if (dbInstance) {
        return Promise.resolve(dbInstance);
    }

    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => {
            console.error('[DB] Failed to open database:', request.error);
            reject(request.error);
        };

        request.onsuccess = () => {
            dbInstance = request.result;
            dbInstance.onversionchange = () => {
                dbInstance.close();
                dbInstance = null;
                console.warn('[DB] Database version changed, connection closed');
            };
            resolve(dbInstance);
        };

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            const tx = event.target.transaction;
            console.log(`[DB] Upgrading database to version ${DB_VERSION}`);

            for (const [storeName, config] of Object.entries(STORES)) {
                let store;
                if (!db.objectStoreNames.contains(storeName)) {
                    store = db.createObjectStore(storeName, { keyPath: config.keyPath });
                    console.log(`[DB] Created store: ${storeName}`);
                } else {
                    store = tx.objectStore(storeName);
                }
                
                // Create any missing indexes
                if (config.indexes) {
                    for (const idx of config.indexes) {
                        if (!store.indexNames.contains(idx.name)) {
                            store.createIndex(idx.name, idx.keyPath, { unique: idx.unique || false });
                            console.log(`[DB] Created index: ${storeName}.${idx.name}`);
                        }
                    }
                }
            }
        };
    });
}

/**
 * Gets a transaction for the specified stores.
 * @param {string|string[]} storeNames - Store name(s) to include in transaction
 * @param {'readonly'|'readwrite'} mode - Transaction mode
 * @returns {Promise<IDBTransaction>}
 */
async function getTransaction(storeNames, mode = 'readonly') {
    const db = await openDatabase();
    const names = Array.isArray(storeNames) ? storeNames : [storeNames];
    return db.transaction(names, mode);
}

/**
 * Wraps an IDBRequest in a Promise.
 * @param {IDBRequest} request - IndexedDB request
 * @returns {Promise<any>}
 */
function promisifyRequest(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Wraps an IDBTransaction completion in a Promise.
 * @param {IDBTransaction} tx - IndexedDB transaction
 * @returns {Promise<void>}
 */
function promisifyTransaction(tx) {
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
    });
}

/**
 * Gets a single record by key.
 * @param {string} storeName - Object store name
 * @param {any} key - Record key
 * @returns {Promise<any|undefined>}
 */
export async function get(storeName, key) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    return promisifyRequest(store.get(key));
}

/**
 * Gets all records from a store.
 * @param {string} storeName - Object store name
 * @param {IDBKeyRange} [query] - Optional key range
 * @param {number} [count] - Optional max count
 * @returns {Promise<any[]>}
 */
export async function getAll(storeName, query, count) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    return promisifyRequest(store.getAll(query, count));
}

/**
 * Gets all records matching an index value.
 * @param {string} storeName - Object store name
 * @param {string} indexName - Index name
 * @param {any} value - Index value to match
 * @returns {Promise<any[]>}
 */
export async function getAllByIndex(storeName, indexName, value) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const index = store.index(indexName);
    return promisifyRequest(index.getAll(value));
}

/**
 * Gets a single record by index value.
 * @param {string} storeName - Object store name
 * @param {string} indexName - Index name
 * @param {any} value - Index value to match
 * @returns {Promise<any|undefined>}
 */
export async function getByIndex(storeName, indexName, value) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const index = store.index(indexName);
    return promisifyRequest(index.get(value));
}

/**
 * Counts records in a store.
 * @param {string} storeName - Object store name
 * @param {IDBKeyRange} [query] - Optional key range
 * @returns {Promise<number>}
 */
export async function count(storeName, query) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    return promisifyRequest(store.count(query));
}

/**
 * Puts (inserts or updates) a single record.
 * @param {string} storeName - Object store name
 * @param {any} value - Record to store
 * @returns {Promise<any>} The key of the stored record
 */
export async function put(storeName, value) {
    const tx = await getTransaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const result = promisifyRequest(store.put(value));
    await promisifyTransaction(tx);
    return result;
}

/**
 * Puts multiple records in a single transaction.
 * @param {string} storeName - Object store name
 * @param {any[]} values - Records to store
 * @returns {Promise<void>}
 */
export async function putAll(storeName, values) {
    if (values.length === 0) return;
    const tx = await getTransaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    for (const value of values) {
        store.put(value);
    }
    await promisifyTransaction(tx);
}

/**
 * Deletes a record by key.
 * @param {string} storeName - Object store name
 * @param {any} key - Record key
 * @returns {Promise<void>}
 */
export async function del(storeName, key) {
    const tx = await getTransaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.delete(key);
    await promisifyTransaction(tx);
}

/**
 * Clears all records from a store.
 * @param {string} storeName - Object store name
 * @returns {Promise<void>}
 */
export async function clear(storeName) {
    const tx = await getTransaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.clear();
    await promisifyTransaction(tx);
}

/**
 * Clears all stores (full database reset).
 * @returns {Promise<void>}
 */
export async function clearAll() {
    const db = await openDatabase();
    const storeNames = Array.from(db.objectStoreNames);
    const tx = db.transaction(storeNames, 'readwrite');
    for (const name of storeNames) {
        tx.objectStore(name).clear();
    }
    await promisifyTransaction(tx);
    console.log('[DB] All stores cleared');
}

/**
 * Iterates over records with a cursor.
 * @param {string} storeName - Object store name
 * @param {function(any): boolean|void} callback - Called for each record, return false to stop
 * @param {Object} [options] - Options
 * @param {IDBKeyRange} [options.query] - Key range
 * @param {IDBCursorDirection} [options.direction] - Cursor direction
 * @returns {Promise<void>}
 */
export async function iterate(storeName, callback, options = {}) {
    const tx = await getTransaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const request = store.openCursor(options.query, options.direction);

    let result = new Promise((resolve, reject) => {
        request.onsuccess = () => {
            const cursor = request.result;
            if (cursor) {
                const shouldContinue = callback(cursor.value);
                if (shouldContinue !== false) {
                    cursor.continue();
                } else {
                    resolve();
                }
            } else {
                resolve();
            }
        };
        request.onerror = () => reject(request.error);
    });

    await promisifyTransaction(tx);
    return result;
}

/**
 * Executes a batch of operations in a single transaction.
 * @param {Array<{store: string, op: 'put'|'delete'|'clear', key?: any, value?: any}>} operations
 * @returns {Promise<void>}
 */
export async function batch(operations) {
    if (operations.length === 0) return;

    const storeNames = [...new Set(operations.map(op => op.store))];
    const tx = await getTransaction(storeNames, 'readwrite');

    for (const op of operations) {
        const store = tx.objectStore(op.store);
        switch (op.op) {
            case 'put':
                store.put(op.value);
                break;
            case 'delete':
                store.delete(op.key);
                break;
            case 'clear':
                store.clear();
                break;
        }
    }

    await promisifyTransaction(tx);
}

/**
 * Deletes the entire database.
 * @returns {Promise<void>}
 */
export async function deleteDatabase() {
    if (dbInstance) {
        dbInstance.close();
        dbInstance = null;
    }
    return new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(DB_NAME);
        request.onsuccess = () => {
            console.log('[DB] Database deleted');
            resolve();
        };
        request.onerror = () => reject(request.error);
        request.onblocked = () => {
            console.warn('[DB] Database deletion blocked');
        };
    });
}

/**
 * Initializes the database connection.
 * @returns {Promise<void>}
 */
export async function init() {
    await openDatabase();
    console.log('[DB] Database initialized');
}

/**
 * Closes the database connection.
 */
export function close() {
    if (dbInstance) {
        dbInstance.close();
        dbInstance = null;
        console.log('[DB] Database connection closed');
    }
}

export { DB_NAME, DB_VERSION, STORES };

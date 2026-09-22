/**
 * @typedef {Object} StorageStartupOptions
 * @property {'plaintext'|'encrypted'|'migrated'} mode
 * @property {import('stellar-private-payments').DatabaseKeyProvider} [keyProvider]
 * @property {string} [workerUrl]
 */

/**
 * Own one storage opening per page. Configure before the first open attempt;
 * retries keep the same mode/provider, so an unlock failure cannot select the
 * stale plaintext database. The provider may prompt again or obtain a new key
 * on a later attempt. No key bytes or selection are persisted by this module.
 *
 * Encrypted startup opens existing data only. Database creation, recoverable
 * key storage and migration actions belong to explicit provisioning flows.
 * `migrated` authenticates the migration control record before selecting data;
 * unfinished/aborted migrations require an explicit decision outside startup.
 *
 * @param {typeof import('stellar-private-payments').Storage} storageApi
 * @param {() => Promise<unknown>} initialize
 */
export function createStorageStartup(storageApi, initialize) {
    /** @type {StorageStartupOptions} */
    let options = { mode: 'plaintext' };
    let started = false;
    let opening = null;

    return {
        /** @param {StorageStartupOptions} selected */
        configure(selected) {
            if (started) {
                throw new Error('Storage startup is already configured for this page');
            }
            if (!selected || !['plaintext', 'encrypted', 'migrated'].includes(selected.mode)) {
                throw new TypeError('Storage mode must be plaintext, encrypted or migrated');
            }
            if (Object.keys(selected).some(key => !['mode', 'keyProvider', 'workerUrl'].includes(key))) {
                throw new TypeError('Unsupported storage startup option; startup only opens existing encrypted data');
            }
            if (selected.mode === 'plaintext' && selected.keyProvider !== undefined) {
                throw new TypeError('Plaintext storage does not accept a keyProvider');
            }
            if (selected.mode !== 'plaintext' && typeof selected.keyProvider !== 'function') {
                throw new TypeError('Encrypted storage requires a keyProvider');
            }
            if (selected.workerUrl !== undefined &&
                (typeof selected.workerUrl !== 'string' || !selected.workerUrl.trim())) {
                throw new TypeError('workerUrl must be a nonempty string');
            }
            options = {
                mode: selected.mode,
                keyProvider: selected.keyProvider,
                workerUrl: selected.workerUrl,
            };
        },
        open() {
            // Freeze synchronously, before WASM initialization or provider awaits.
            started = true;
            if (!opening) {
                opening = Promise.resolve().then(async () => {
                    await initialize();
                    if (options.mode === 'plaintext') {
                        return storageApi.open({ workerUrl: options.workerUrl });
                    }
                    const keyed = {
                        keyProvider: options.keyProvider,
                        workerUrl: options.workerUrl,
                        createNew: false,
                    };
                    if (options.mode === 'migrated') {
                        const migration = await storageApi.openMigration(keyed);
                        try {
                            const status = await migration.status();
                            if (!['active', 'cleaning', 'complete'].includes(status)) {
                                throw new Error(`Migration requires explicit action before startup (${status})`);
                            }
                        } finally {
                            // Release both pools before the data worker takes ownership.
                            // A failed close must also prevent opening data.
                            await migration.close();
                        }
                    }
                    return storageApi.openEncrypted(keyed);
                }).catch(error => {
                    opening = null;
                    throw error;
                });
            }
            return opening;
        },
    };
}

// Application policy, separate from DOM and SDK transports so failure paths are testable.
import { createBackup, readBackup, decryptBackup } from './database-backup.js';
export const STORAGE_SELECTION = 'spp.storage-access.v1';
export const DATABASE_ID = 'spp.encrypted.db';

export function createStorageAccess({ vault, store, makeVault, selection, open, configure, close, reload, exportDatabase, restoreDatabase, openMigration, recoverMigration }) {
    let session = null;
    let busy = false;
    let stopped = false;
    const exclusive = async operation => {
        if (busy || stopped) throw new Error('Storage access is busy or locked; reload before retrying.');
        busy = true;
        try { return await operation(); } finally { busy = false; }
    };
    const select = mode => selection.setItem(STORAGE_SELECTION, mode);
    async function openPendingMigration(candidate) {
        const options = { keyProvider: candidate.keyProvider };
        try { return await openMigration(options); }
        catch (error) {
            // Recovery refuses existing candidates and requires absent setup or
            // the matching key/source-bound initialization marker.
            try { return await recoverMigration(options); }
            catch { throw error; }
        }
    }
    async function migrate(password, action) {
        if (selection.getItem(STORAGE_SELECTION) !== 'migration-pending') throw new Error('No migration is pending.');
        const candidate = await vault.unlockPassword(password);
        let migration;
        try {
            migration = await openPendingMigration(candidate);
            let phase = await migration.status();
            if (action === 'prepare') {
                if (phase === 'aborted') phase = await migration.restart();
                if (phase === 'copying') phase = await migration.prepare();
            } else if (action === 'abort') {
                phase = await migration.abort();
            } else if (action === 'activate') {
                if (phase === 'prepared') phase = await migration.activate();
                if (['active', 'cleaning', 'complete'].includes(phase)) phase = await migration.finish();
                if (phase !== 'complete') throw new Error('Prepare the encrypted copy before activating it.');
            }
            // Close both pools before allowing the ordinary storage worker to open.
            await migration.close();
            migration = null;
            if (phase === 'complete') select('backup-required');
            return phase;
        } finally {
            try { await migration?.close(); } finally { candidate.lock(); }
        }
    }
    async function probe(keySession, createNew) {
        const db = await open({ keyProvider: keySession.keyProvider, createNew });
        try { await db.close(); } finally { db.free(); }
    }
    async function accept(candidate) {
        try {
            if (selection.getItem(STORAGE_SELECTION) === 'restore-pending') throw new Error('Complete the interrupted restore with its original backup file first.');
            if (selection.getItem(STORAGE_SELECTION) === 'migration-pending') throw new Error('Complete the pending migration before unlocking.');
            await probe(candidate, false);
            select('encrypted');
            configure({ mode: 'encrypted', keyProvider: candidate.keyProvider });
            session = candidate;
        } catch (error) { candidate.lock(); throw error; }
    }
    return {
        async status() {
            const mode = selection.getItem(STORAGE_SELECTION);
            if (mode !== null && !['provisioning', 'backup-required', 'encrypted', 'restore-pending', 'migration-pending'].includes(mode)) {
                throw new Error('Invalid storage selection. Restore your key backup; plaintext fallback is disabled.');
            }
            const state = await vault.status();
            return { ...state, required: mode !== null || state.exists,
                provisioning: mode === 'provisioning' || mode === 'backup-required',
                restoring: mode === 'restore-pending',
                migrating: mode === 'migration-pending',
                needsCreation: mode === 'provisioning' };
        },
        startMigration: password => exclusive(async () => {
            const mode = selection.getItem(STORAGE_SELECTION);
            if (mode !== null && mode !== 'migration-pending') throw new Error('Encrypted storage is already selected.');
            if ((await vault.status()).exists) throw new Error('A key already exists. Resume the pending migration instead.');
            select('migration-pending');
            const candidate = await vault.createPassword(password);
            candidate.lock();
            return migrate(password, 'prepare');
        }),
        prepareMigration: password => exclusive(() => migrate(password, 'prepare')),
        abortMigration: password => exclusive(() => migrate(password, 'abort')),
        activateMigration: password => exclusive(() => migrate(password, 'activate')),
        recoverMigrationState: password => exclusive(async () => {
            if (selection.getItem(STORAGE_SELECTION) === 'restore-pending') throw new Error('Complete the pending restore first.');
            const candidate = await vault.unlockPassword(password);
            try {
                const migration = await openPendingMigration(candidate);
                let phase;
                try { phase = await migration.status(); } finally { await migration.close(); }
                select(phase === 'complete' ? 'backup-required' : 'migration-pending');
                return phase;
            } finally { candidate.lock(); }
        }),
        setup: password => exclusive(async () => {
            if ((await vault.status()).exists) throw new Error('A key already exists. Unlock or resume setup instead.');
            const mode = selection.getItem(STORAGE_SELECTION);
            if (mode !== null && mode !== 'provisioning') throw new Error('Encrypted storage is already selected. Restore its key backup instead of creating a replacement.');
            select('provisioning'); // Fail closed even if key persistence or database creation is interrupted.
            const candidate = await vault.createPassword(password);
            try { await probe(candidate, true); } finally { candidate.lock(); }
            select('backup-required');
        }),
        resumeSetup: password => exclusive(async () => {
            if (selection.getItem(STORAGE_SELECTION) !== 'provisioning') throw new Error('No interrupted setup to resume.');
            const candidate = await vault.unlockPassword(password);
            try { await probe(candidate, true); } finally { candidate.lock(); }
            select('backup-required');
        }),
        unlockPassword: password => exclusive(async () => accept(await vault.unlockPassword(password))),
        unlockPasskey: () => exclusive(async () => accept(await vault.unlockPasskey())),
        backup: password => exclusive(async () => {
            // Read once: authenticate exactly the envelope being exported, even during concurrent changes.
            const record = await store.read(DATABASE_ID);
            const temporary = makeVault({ read: async () => record });
            const candidate = await temporary.unlockPassword(password);
            candidate.lock();
            return JSON.stringify({ format: 'spp-wrapped-database-key', version: 1, record }, null, 2);
        }),
        completeBackup: password => exclusive(async () => {
            const record = await store.read(DATABASE_ID);
            const candidate = await makeVault({ read: async () => record }).unlockPassword(password);
            try {
                const snapshot = await exportDatabase(candidate.keyProvider);
                return await createBackup(record, snapshot, candidate.keyProvider);
            } finally { candidate.lock(); }
        }),
        restoreComplete: (bytes, password) => exclusive(async () => {
            if (selection.getItem(STORAGE_SELECTION) === 'migration-pending') throw new Error('Complete the pending migration first.');
            const { record } = readBackup(bytes);
            const current = await store.read(DATABASE_ID);
            if (current !== null && (selection.getItem(STORAGE_SELECTION) !== 'restore-pending' ||
                JSON.stringify(current) !== JSON.stringify(record))) throw new Error('A key already exists. Complete restore will not overwrite it.');
            const candidate = await makeVault({ read: async () => record }).unlockPassword(password);
            try {
                const snapshot = await decryptBackup(bytes, candidate.keyProvider);
                select('restore-pending');
                // The selected archive remains the recovery source until both stores commit.
                // The worker retains an authenticated completion marker for idempotent retry
                // if this page dies before the IndexedDB key record commits.
                await restoreDatabase(snapshot, candidate.keyProvider);
                if (current === null) await store.write(DATABASE_ID, record, null);
                select('encrypted');
            } finally { candidate.lock(); }
        }),
        restore: (text, password) => exclusive(async () => {
            if (typeof text !== 'string' || text.length > 16384) throw new Error('Invalid key backup size.');
            const backup = JSON.parse(text);
            if (!backup || Object.keys(backup).sort().join(',') !== 'format,record,version' ||
                backup.format !== 'spp-wrapped-database-key' || backup.version !== 1) throw new Error('Unsupported key backup.');
            if (await store.read(DATABASE_ID)) throw new Error('A key already exists. Recovery will not overwrite it.');
            const temporary = makeVault({ read: async () => backup.record });
            const candidate = await temporary.unlockPassword(password);
            try {
                // Authenticate the existing database before making restored metadata authoritative.
                if (selection.getItem(STORAGE_SELECTION) === 'migration-pending') {
                    const migration = await openPendingMigration(candidate);
                    try { await migration.status(); } finally { await migration.close(); }
                } else {
                    await probe(candidate, false);
                    select('encrypted');
                }
                await store.write(DATABASE_ID, backup.record, null);
            } finally { candidate.lock(); }
        }),
        async lock() {
            stopped = true;
            try { await close(); }
            finally {
                session?.lock();
                session = null;
                // Reload discards application/account state and workers, including when close fails.
                reload();
            }
        },
    };
}

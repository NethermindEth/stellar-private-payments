import assert from 'node:assert/strict';
import test from 'node:test';
import { createStorageAccess, STORAGE_SELECTION, DATABASE_ID } from '../js/storage-access.js';
import { DatabaseKeyVault } from '../../sdk/web/js/key-vault.js';
import { MemoryKeyStore } from '../../sdk/web/scripts/key-vault-fixture.mjs';

const password = 'synthetic application password';
function fixture(migrationOptions = {}) {
    const store = new MemoryKeyStore();
    const makeVault = store => new DatabaseKeyVault({ databaseId: DATABASE_ID, store });
    const vault = makeVault(store);
    const modes = new Map();
    const selection = { getItem: k => modes.get(k) ?? null, setItem: (k, v) => modes.set(k, v) };
    const state = { key: null, failOpen: false, failClose: false, events: [] };
    function controller() {
        return createStorageAccess({ store, vault, makeVault, selection,
            open: async ({ keyProvider, createNew }) => {
                state.events.push(createNew ? 'create' : 'open');
                assert(store.value !== null || !createNew, 'key persisted before creation');
                if (state.failOpen) throw Error('open failed');
                const key = keyProvider(DATABASE_ID, createNew ? 'create' : 'open');
                if (createNew) { if (state.key) throw Error('already exists'); state.key = new Uint8Array(key); }
                else { if (!state.key) throw Error('database missing'); assert.deepEqual(key, state.key); }
                return { close: async () => { state.events.push('probe close'); }, free: () => state.events.push('free') };
            },
            configure: options => { state.options = options; state.events.push('configure'); },
            close: async () => { state.events.push('close'); if (state.failClose) throw Error('close failed'); },
            reload: () => state.events.push('reload'),
            ...migrationOptions,
        });
    }
    return { store, vault, selection, state, controller, access: controller() };
}

test('migration retains its key across setup failure, blocks unlock and resumes interrupted activation', async () => {
    let phase = 'copying', failOpen = true, failFinish = true, savedKey;
    const migration = {
        status: async () => phase,
        prepare: async () => phase = 'prepared',
        activate: async () => phase = 'active',
        finish: async () => { if (failFinish) throw Error('cleanup interrupted'); return phase = 'complete'; },
        close: async () => {},
    };
    const f = fixture({
        openMigration: async ({ keyProvider }) => {
            const key = keyProvider(DATABASE_ID, 'open');
            if (savedKey) assert.deepEqual(key, savedKey); else savedKey = new Uint8Array(key);
            if (failOpen) throw Error('setup interrupted');
            return migration;
        },
        recoverMigration: async () => { throw Error('setup recovery unavailable'); },
    });
    await assert.rejects(f.access.startMigration(password), /setup interrupted/);
    const envelope = structuredClone(f.store.value);
    assert.equal((await f.access.status()).migrating, true);
    await assert.rejects(f.access.startMigration(password), /key already exists/);
    await assert.rejects(f.access.unlockPassword(password), /pending migration/);
    await assert.rejects(f.access.restoreComplete(new Uint8Array(), password), /pending migration/);
    assert.equal(f.state.events.length, 0);
    failOpen = false;
    assert.equal(await f.controller().prepareMigration(password), 'prepared');
    await assert.rejects(f.access.activateMigration(password), /cleanup interrupted/);
    assert.equal(phase, 'active');
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'migration-pending');
    await assert.rejects(f.access.unlockPassword(password), /pending migration/);
    failFinish = false;
    assert.equal(await f.controller().activateMigration(password), 'complete');
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'backup-required');
    assert.deepEqual(f.store.value, envelope);
});

test('migration uses authenticated setup recovery and locks key sessions after operation failure', async () => {
    let supplied;
    const f = fixture({
        openMigration: async () => { throw Error('missing setup'); },
        recoverMigration: async ({ keyProvider }) => {
            supplied = keyProvider(DATABASE_ID, 'open');
            return { status: async () => 'copying', prepare: async () => { throw Error('copy failed'); }, close: async () => {} };
        },
    });
    await assert.rejects(f.access.startMigration(password), /copy failed/);
    assert(supplied.every(b => b === 0));
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'migration-pending');
    assert.equal(f.state.options, undefined);
    const backup = await f.access.backup(password);
    f.store.value = null;
    await f.access.restore(backup, password);
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'migration-pending');
    assert.equal((await f.vault.status()).exists, true);
    f.selection.setItem(STORAGE_SELECTION, null);
    // Map-backed fixture treats a stored null as an absent selection.
    await assert.rejects(f.access.recoverMigrationState('wrong'), /Cannot unlock/);
    assert.equal(f.selection.getItem(STORAGE_SELECTION), null);
    assert.equal(await f.access.recoverMigrationState(password), 'copying');
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'migration-pending');
});

test('plaintext default; encrypted provisioning persists across page controllers and never overwrites a key', async () => {
    const f = fixture();
    assert.equal((await f.access.status()).required, false);
    await f.access.setup(password);
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'backup-required');
    assert.equal((await f.access.status()).needsCreation, false);
    assert.equal((await f.controller().status()).required, true);
    await assert.rejects(f.access.setup(password), /already exists/);
    await assert.rejects(f.access.resumeSetup(password), /No interrupted setup/);
    await f.access.unlockPassword(password);
    assert.equal(f.selection.getItem(STORAGE_SELECTION), 'encrypted');
    assert.equal(f.state.options.mode, 'encrypted');
});

test('wrong password cannot configure storage or alter the wrapped key', async () => {
    const f = fixture(); await f.access.setup(password);
    const before = structuredClone(f.store.value);
    const count = f.state.events.length;
    await assert.rejects(f.access.unlockPassword('wrong'), /Cannot unlock/);
    assert.deepEqual(f.store.value, before);
    assert.equal(f.state.events.length, count);
    assert.equal(f.state.options, undefined);
});

test('interrupted database creation retains the same key and can be explicitly resumed', async () => {
    const f = fixture(); f.state.failOpen = true;
    await assert.rejects(f.access.setup(password), /open failed/);
    const before = structuredClone(f.store.value);
    assert.equal((await f.controller().status()).provisioning, true);
    assert.equal((await f.controller().status()).needsCreation, true);
    f.state.failOpen = false;
    await f.controller().resumeSetup(password);
    assert.deepEqual(f.store.value, before);
    await f.access.unlockPassword(password);
});

test('backup authenticates and restores the matching database without replacing an existing envelope', async () => {
    const f = fixture(); await f.access.setup(password);
    const backup = await f.access.backup(password);
    assert(!backup.includes(password));
    assert(!backup.includes(Buffer.from(f.state.key).toString('base64')));
    await assert.rejects(f.access.restore(backup, password), /will not overwrite/);
    f.store.value = null;
    await assert.rejects(f.access.restore(backup, 'wrong'), /Cannot unlock/);
    assert.equal(f.store.value, null);
    await f.access.restore(backup, password);
    await f.access.unlockPassword(password);
    assert.deepEqual(f.state.options.keyProvider(DATABASE_ID, 'open'), f.state.key);
});

test('missing or mismatched database refuses recovery without persisting the envelope', async () => {
    const f = fixture(); await f.access.setup(password);
    const backup = await f.access.backup(password);
    f.store.value = null; f.state.key = null;
    await assert.rejects(f.access.restore(backup, password), /database missing/);
    assert.equal(f.store.value, null);
    f.state.key = new Uint8Array(32);
    await assert.rejects(f.access.restore(backup, password));
    assert.equal(f.store.value, null);
});

test('invalid backup, corrupt selection and missing metadata fail closed', async () => {
    const f = fixture();
    await assert.rejects(f.access.restore('{}', password), /Unsupported/);
    await assert.rejects(f.access.restore('x'.repeat(16385), password), /size/);
    f.selection.setItem(STORAGE_SELECTION, 'unknown');
    await assert.rejects(f.access.status(), /Invalid storage selection/);
    f.selection.setItem(STORAGE_SELECTION, 'encrypted');
    assert.equal((await f.access.status()).required, true);
    await assert.rejects(f.access.setup(password), /Restore its key backup/);
    assert.equal(f.store.value, null);
    await assert.rejects(f.access.unlockPassword(password), /No wrapped/);
    assert.equal(f.state.options, undefined);
});

test('lock closes storage before zeroizing the provider and reloads even after close failure', async () => {
    for (const failClose of [false, true]) {
        const f = fixture(); await f.access.setup(password); await f.access.unlockPassword(password);
        const bytes = f.state.options.keyProvider(DATABASE_ID, 'open');
        f.state.failClose = failClose;
        if (failClose) await assert.rejects(f.access.lock(), /close failed/); else await f.access.lock();
        assert(bytes.every(b => b === 0));
        assert.deepEqual(f.state.events.slice(-2), ['close', 'reload']);
        await assert.rejects(f.access.unlockPassword(password), /locked/);
    }
});

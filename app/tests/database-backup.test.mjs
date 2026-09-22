import assert from 'node:assert/strict';
import test from 'node:test';
import { createBackup, readBackup, decryptBackup } from '../js/database-backup.js';
import { createStorageAccess, DATABASE_ID, STORAGE_SELECTION } from '../js/storage-access.js';
import { DatabaseKeyVault } from '../../sdk/web/js/key-vault.js';
import { MemoryKeyStore } from '../../sdk/web/scripts/key-vault-fixture.mjs';
const password = 'synthetic complete backup password';

async function fixture() {
    const original = new MemoryKeyStore();
    const vault = new DatabaseKeyVault({ store: original });
    const session = await vault.createPassword(password);
    const record = await original.read(DATABASE_ID);
    const snapshot = crypto.getRandomValues(new Uint8Array(4096));
    const archive = await createBackup(record, snapshot, session.keyProvider);
    return { record, snapshot, archive, session };
}

test('complete archive binds exact key envelope and encrypted snapshot, with randomized encryption', async () => {
    const f = await fixture();
    assert.deepEqual(readBackup(f.archive).record, f.record);
    assert.deepEqual(await decryptBackup(f.archive, f.session.keyProvider), f.snapshot);
    assert.notDeepEqual(await createBackup(f.record, f.snapshot, f.session.keyProvider), f.archive);
    for (const offset of [f.archive.length - 1, f.archive.length - 32]) {
        const damaged = f.archive.slice(); damaged[offset] ^= 1;
        await assert.rejects(decryptBackup(damaged, f.session.keyProvider), /authentication failed/);
    }
    // Alter valid JSON metadata, retaining a syntactically valid archive.
    const damaged = f.archive.slice();
    const text = new TextDecoder().decode(damaged);
    const offset = text.indexOf('"revision":1') + '"revision":'.length;
    damaged[offset] = '2'.charCodeAt(0);
    await assert.rejects(decryptBackup(damaged, f.session.keyProvider), /authentication failed/);
    await assert.rejects(decryptBackup(f.archive, () => new Uint8Array(32)), /authentication failed/);
    assert.throws(() => readBackup(new Uint8Array(20)), /supported/);
    f.session.lock();
});

test('complete restore authenticates before writes and supports metadata-commit retry', async () => {
    const f = await fixture();
    const store = new MemoryKeyStore(); const values = new Map(); const events = [];
    const selection = { getItem: k => values.get(k) ?? null, setItem: (k,v) => values.set(k,v) };
    const makeVault = store => new DatabaseKeyVault({ store });
    const access = createStorageAccess({ store, vault: makeVault(store), makeVault, selection,
        restoreDatabase: async (bytes, provider) => {
            events.push('restore');
            assert.deepEqual(bytes, f.snapshot);
            assert.deepEqual(provider(DATABASE_ID, 'open'), f.session.keyProvider(DATABASE_ID, 'open'));
        } });
    await assert.rejects(access.restoreComplete(f.archive, 'wrong'), /Cannot unlock/);
    assert.equal(values.size, 0); assert.deepEqual(events, []);
    const damaged = f.archive.slice(); damaged[damaged.length - 1] ^= 1;
    await assert.rejects(access.restoreComplete(damaged, password), /authentication failed/);
    assert.equal(values.size, 0); assert.deepEqual(events, []);
    store.failWrites = true;
    await assert.rejects(access.restoreComplete(f.archive, password), /storage failure/);
    assert.equal(selection.getItem(STORAGE_SELECTION), 'restore-pending');
    assert.equal(store.value, null);
    store.failWrites = false;
    await access.restoreComplete(f.archive, password);
    assert.equal(selection.getItem(STORAGE_SELECTION), 'encrypted');
    assert.deepEqual(store.value, f.record);
    await assert.rejects(access.restoreComplete(f.archive, password), /will not overwrite/);
    assert.equal(events.length, 2);
    f.session.lock();
});

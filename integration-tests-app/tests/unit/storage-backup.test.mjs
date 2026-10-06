import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { DEFAULT_DIRECTORY, STORAGE_RECORD_KEY, exportStorageBackup, importStorageBackup, parseBackup, resetStorage, hasEncryptedStorage } from '../../../app/js/storage-backup.js';
import { openWalletStorage } from '../../../app/js/storage-key.js';

class Directory {
  kind = 'directory';
  children = new Map();
  async *entries() { yield* this.children; }
  async getDirectoryHandle(name, { create = false } = {}) {
    if (!this.children.has(name)) {
      if (!create) throw new Error('missing directory');
      this.children.set(name, new Directory());
    }
    const entry = this.children.get(name);
    if (entry.kind !== 'directory') throw new Error('not a directory');
    return entry;
  }
  async getFileHandle(name, { create = false } = {}) {
    if (!this.children.has(name)) {
      if (!create) throw new Error('missing file');
      const entry = { kind: 'file', bytes: new Uint8Array(),
        getFile: async () => ({ size: entry.bytes.length, arrayBuffer: async () => entry.bytes.slice().buffer }),
        createWritable: async () => ({ write: async bytes => { entry.bytes = bytes.slice(); }, close: async () => {}, abort: async () => {} }),
      };
      this.children.set(name, entry);
    }
    return this.children.get(name);
  }
  async removeEntry(name) { this.children.delete(name); }
}
function records() {
  const values = new Map();
  return { get length() { return values.size; }, key: i => [...values.keys()][i], getItem: k => values.get(k) ?? null,
    setItem: (k, v) => values.set(k, v), removeItem: k => values.delete(k) };
}
async function fixture() {
  const root = new Directory();
  const store = records();
  store.setItem(STORAGE_RECORD_KEY, JSON.stringify({ origin: 'https://app.test', pending: false, version: 1, address: 'owner', envelope: 'wrapped' }));
  const directory = await root.getDirectoryHandle(DEFAULT_DIRECTORY, { create: true });
  const opaque = await directory.getDirectoryHandle('.opaque', { create: true });
  const file = await opaque.getFileHandle('encrypted-file', { create: true });
  file.bytes = new Uint8Array([0, 255, 1, 128]);
  return { root, store, directory };
}

test('encrypted backup round trips opaque bytes and commits envelope plus directory only after validation', async () => {
  const { root, store, directory } = await fixture();
  const original = store.getItem(STORAGE_RECORD_KEY);
  const text = await exportStorageBackup({ root, records: store });
  const backup = parseBackup(text, 'https://app.test');
  assert.deepEqual(backup.files[0].bytes, new Uint8Array([0, 255, 1, 128]));
  await importStorageBackup({ backup, root, records: store, crypto: webcrypto, validate: async record => {
    assert.equal(store.getItem(STORAGE_RECORD_KEY), original);
    assert.notEqual(record.directory, DEFAULT_DIRECTORY);
    const stage = await root.getDirectoryHandle(record.directory);
    const opaque = await stage.getDirectoryHandle('.opaque');
    assert.deepEqual((await opaque.getFileHandle('encrypted-file')).bytes, backup.files[0].bytes);
  } });
  const imported = JSON.parse(store.getItem(STORAGE_RECORD_KEY));
  assert.notEqual(imported.directory, DEFAULT_DIRECTORY);
  assert.equal(imported.envelope, 'wrapped');
  assert.equal(await root.getDirectoryHandle(DEFAULT_DIRECTORY), directory);
});

test('failed validation or envelope persistence preserves current storage and removes staging', async () => {
  for (const failWrite of [false, true]) {
    const { root, store, directory } = await fixture();
    const original = store.getItem(STORAGE_RECORD_KEY);
    const backup = parseBackup(await exportStorageBackup({ root, records: store }), 'https://app.test');
    if (failWrite) store.setItem = () => { throw new Error('quota exceeded'); };
    await assert.rejects(importStorageBackup({ backup, root, records: store, crypto: webcrypto,
      validate: async () => { if (!failWrite) throw new Error('wrong key or damaged database'); },
    }));
    assert.equal(store.getItem(STORAGE_RECORD_KEY), original);
    assert.equal(root.children.size, 1);
    assert.equal(await root.getDirectoryHandle(DEFAULT_DIRECTORY), directory);
  }
});

test('backup validation rejects wrong origin, traversal, duplicate paths and damaged encoding', async () => {
  const { root, store } = await fixture();
  const text = await exportStorageBackup({ root, records: store });
  assert.throws(() => parseBackup(text, 'https://other.test'), /different app origin/);
  for (const modify of [
    b => { b.files[0].path = '../other'; },
    b => { b.files.push(b.files[0]); },
    b => { b.files[0].data = '!'; },
    b => { b.record.pending = true; },
  ]) {
    const backup = JSON.parse(text); modify(backup);
    assert.throws(() => parseBackup(JSON.stringify(backup), 'https://app.test'));
  }
});

test('missing envelope never enrolls over surviving encrypted data', async () => {
  const { root } = await fixture();
  assert.equal(await hasEncryptedStorage(root), true);
  await assert.rejects(openWalletStorage({
    records: records(), origin: 'https://app.test', crypto: webcrypto,
    locks: { request: async (_name, _opts, cb) => cb() },
    hasExistingStorage: () => hasEncryptedStorage(root),
    getAddress: () => assert.fail('must not enroll'),
  }), { code: 'storage-recovery-required' });
});

test('reset deletes encrypted generations and legacy signer lists, preserving unrelated origin data', async () => {
  const { root, store } = await fixture();
  await root.getDirectoryHandle(`${DEFAULT_DIRECTORY}-${webcrypto.randomUUID()}`, { create: true });
  await root.getDirectoryHandle('unrelated', { create: true });
  store.setItem('poolstellar_signers:owner', '[]');
  store.setItem('explorer', 'keep');
  await resetStorage({ root, records: store });
  assert.equal(store.getItem(STORAGE_RECORD_KEY), null);
  assert.equal(store.getItem('poolstellar_signers:owner'), null);
  assert.equal(store.getItem('explorer'), 'keep');
  assert.deepEqual([...root.children.keys()], ['unrelated']);
  assert.equal(await hasEncryptedStorage(root), false);
});

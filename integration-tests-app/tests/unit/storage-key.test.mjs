import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { openPasswordStorage } from '../../../app/js/storage-key.js';

function fixture() {
  const values = new Map();
  const requests = [];
  const records = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value) };
  const keys = [];
  let databaseKey;
  const options = {
    records, origin: 'https://storage.test', crypto: webcrypto,
    requestPassword: async request => { requests.push(request); return 'test storage password'; },
    storage: { open: async ({ keyProvider, createNew }) => {
      const key = await keyProvider();
      keys.push(key);
      if (createNew && databaseKey) throw new Error('database create/open purpose does not match existing file');
      if (!createNew) assert.deepEqual(key, databaseKey);
      databaseKey = key.slice();
      return { encrypted: true };
    } },
  };
  return { options, values, requests, keys };
}

test('creates and reopens with a password, without calling any wallet signer', async () => {
  const f = fixture();
  assert.deepEqual(await openPasswordStorage(f.options), { encrypted: true });
  const saved = [...f.values.values()][0];
  const record = JSON.parse(saved);
  assert.equal(record.pending, false);
  assert.equal(record.version, 2);
  assert.equal(record.address, undefined);
  assert.equal(record.kdf, 'PBKDF2-SHA-256');
  assert.ok(!saved.includes('test storage password'));
  await openPasswordStorage(f.options);
  assert.deepEqual(f.requests.map(request => request.creating), [true, false]);
  assert.equal([...f.values.values()][0], saved);
  assert.ok(f.keys.every(key => key.every(byte => byte === 0)));
});

test('wrong password preserves records and DB, and a retry can unlock', async () => {
  const f = fixture();
  await openPasswordStorage(f.options);
  const saved = [...f.values.values()][0];
  let attempts = 0;
  f.options.requestPassword = async request => {
    if (attempts++ === 0) return 'wrong password';
    assert.match(request.error, /Incorrect storage password/);
    assert.equal([...f.values.values()][0], saved);
    assert.equal(f.keys.length, 1);
    return 'test storage password';
  };
  await openPasswordStorage(f.options);
  assert.equal(attempts, 2);
  assert.equal([...f.values.values()][0], saved);
});

test('cancellation leaves new storage and records untouched', async () => {
  const f = fixture();
  f.options.requestPassword = async () => { throw new Error('Storage unlocking cancelled.'); };
  await assert.rejects(openPasswordStorage(f.options), /cancelled/);
  assert.equal(f.values.size, 0);
  assert.equal(f.keys.length, 0);
});

test('interrupted DB creation reuses its saved password envelope', async () => {
  const f = fixture();
  await openPasswordStorage(f.options);
  const [name, saved] = [...f.values][0];
  f.values.set(name, JSON.stringify({ ...JSON.parse(saved), pending: true }));
  await openPasswordStorage(f.options);
  assert.equal(JSON.parse(f.values.get(name)).pending, false);
  assert.equal(f.keys.length, 3);
});

test('failure before DB creation retains the key for the next attempt', async () => {
  const f = fixture();
  const open = f.options.storage.open;
  f.options.storage.open = async () => { throw new Error('worker unavailable'); };
  await assert.rejects(openPasswordStorage(f.options), /worker unavailable/);
  const [name, saved] = [...f.values][0];
  assert.equal(JSON.parse(saved).pending, true);
  f.options.storage.open = open;
  await openPasswordStorage(f.options);
  assert.equal(JSON.parse(f.values.get(name)).envelope, JSON.parse(saved).envelope);
});

test('unsupported prior records are preserved without prompting or signing', async () => {
  const f = fixture();
  const old = JSON.stringify({ version: 1, address: 'previous-account', salt: 'old-record' });
  f.values.set('poolstellar_encrypted_storage_v1', old);
  await assert.rejects(openPasswordStorage(f.options), /Existing data has been preserved/);
  assert.equal([...f.values.values()][0], old);
  assert.equal(f.requests.length, 0);
  assert.equal(f.keys.length, 0);
});

test('origin mismatch and damaged KDF metadata preserve existing storage', async () => {
  const f = fixture();
  await openPasswordStorage(f.options);
  const [name, saved] = [...f.values][0];
  for (const patch of [{ origin: 'https://other.test' }, { iterations: 1 }, { salt: 'AA==' }]) {
    const changed = JSON.stringify({ ...JSON.parse(saved), ...patch });
    f.values.set(name, changed);
    await assert.rejects(openPasswordStorage(f.options), /Existing data has been preserved/);
    assert.equal(f.values.get(name), changed);
    assert.equal(f.keys.length, 1);
  }
});

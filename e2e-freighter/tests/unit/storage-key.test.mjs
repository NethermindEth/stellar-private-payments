import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { openWalletStorage } from '../../../app/js/storage-key.js';

function fixture() {
  const values = new Map();
  const records = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value) };
  let signature = new Uint8Array(64).fill(7);
  const signedAddresses = [];
  const keys = [];
  let databaseKey;
  const options = {
    records, origin: 'https://storage.test', crypto: webcrypto,
    getAddress: async () => 'owner-a',
    signMessage: async (_, { address }) => {
      signedAddresses.push(address);
      return { signedMessage: Buffer.from(signature).toString('base64'), signerAddress: address };
    },
    verifySignature: async () => true,
    storage: { open: async ({ keyProvider, createNew }) => {
      const key = await keyProvider();
      keys.push(key);
      if (createNew && databaseKey) throw new Error('database create/open purpose does not match existing file');
      if (!createNew) assert.deepEqual(key, databaseKey);
      databaseKey = key.slice();
      return { encrypted: true };
    } },
  };
  return { options, values, signedAddresses, keys, setSignature: value => { signature = value; } };
}

test('creates a wrapped random key and reopens with the original storage identity', async () => {
  const f = fixture();
  assert.deepEqual(await openWalletStorage(f.options), { encrypted: true });
  const saved = [...f.values.values()][0];
  assert.equal(JSON.parse(saved).pending, false);
  f.options.getAddress = async () => 'owner-b';
  await openWalletStorage(f.options);
  assert.deepEqual(f.signedAddresses, ['owner-a', 'owner-a', 'owner-a']);
  assert.equal([...f.values.values()][0], saved);
  assert.ok(f.keys.every(key => key.every(byte => byte === 0)));
});

test('wrong signature cannot unwrap or replace an existing key', async () => {
  const f = fixture();
  await openWalletStorage(f.options);
  const saved = [...f.values.values()][0];
  f.setSignature(new Uint8Array(64).fill(8));
  await assert.rejects(openWalletStorage(f.options));
  assert.equal([...f.values.values()][0], saved);
  assert.equal(f.keys.length, 1);
});

test('rejection leaves new storage and key records untouched', async () => {
  const f = fixture();
  f.options.signMessage = async () => { throw new Error('User rejected'); };
  await assert.rejects(openWalletStorage(f.options), /User rejected/);
  assert.equal(f.values.size, 0);
  assert.equal(f.keys.length, 0);
});

test('interrupted DB creation reuses its saved key envelope', async () => {
  const f = fixture();
  await openWalletStorage(f.options);
  const [name, saved] = [...f.values][0];
  f.values.set(name, JSON.stringify({ ...JSON.parse(saved), pending: true }));
  await openWalletStorage(f.options);
  assert.equal(JSON.parse(f.values.get(name)).pending, false);
  assert.equal(f.keys.length, 3);
});

test('invalid wallet signature never creates storage', async () => {
  const f = fixture();
  f.options.verifySignature = async () => false;
  await assert.rejects(openWalletStorage(f.options), /Invalid wallet signature/);
  assert.equal(f.values.size, 0);
  assert.equal(f.keys.length, 0);
});

test('non-reproducible enrollment signatures never create a database or record', async () => {
  const f = fixture();
  let calls = 0;
  f.options.signMessage = async () => ({ signedMessage: Buffer.alloc(64, ++calls).toString('base64'), signerAddress: 'owner-a' });
  await assert.rejects(openWalletStorage(f.options), /reproducible/);
  assert.equal(f.values.size, 0);
  assert.equal(f.keys.length, 0);
});

test('password records are preserved and rejected before requesting a signature', async () => {
  const f = fixture();
  const record = JSON.stringify({ version: 2, kdf: 'PBKDF2-SHA-256' });
  f.values.set('poolstellar_encrypted_storage_v1', record);
  await assert.rejects(openWalletStorage(f.options), /metadata/);
  assert.equal(f.values.get('poolstellar_encrypted_storage_v1'), record);
  assert.equal(f.signedAddresses.length, 0);
});

test('damaged key metadata and origin changes are rejected before signing', async () => {
  for (const patch of [{ salt: 'AA==' }, { iv: 'AA==' }, { envelope: 'AA==' }, { origin: 'https://other.test' }]) {
    const f = fixture();
    await openWalletStorage(f.options);
    const name = 'poolstellar_encrypted_storage_v1';
    const damaged = JSON.stringify({ ...JSON.parse(f.values.get(name)), ...patch });
    f.values.set(name, damaged);
    await assert.rejects(openWalletStorage(f.options));
    assert.equal(f.values.get(name), damaged);
    assert.equal(f.signedAddresses.length, 2);
  }
});

test('a different reported signer cannot open existing storage', async () => {
  const f = fixture();
  await openWalletStorage(f.options);
  const saved = [...f.values.values()][0];
  f.options.signMessage = async () => ({ signedMessage: Buffer.alloc(64, 7).toString('base64'), signerAddress: 'owner-b' });
  await assert.rejects(openWalletStorage(f.options), /different account/);
  assert.equal([...f.values.values()][0], saved);
  assert.equal(f.keys.length, 1);
});

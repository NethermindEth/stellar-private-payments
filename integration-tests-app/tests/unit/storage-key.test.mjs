import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { openWalletStorage } from '../../../app/js/storage-key.js';

function lockManager() {
  const queues = new Map();
  return { request(name, { mode }, callback) {
    assert.equal(mode, 'exclusive');
    const result = (queues.get(name) ?? Promise.resolve()).then(callback);
    queues.set(name, result.catch(() => {}));
    return result;
  } };
}

function fixture() {
  const values = new Map();
  const records = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value) };
  let signature = new Uint8Array(64).fill(7);
  const signedAddresses = [];
  const keys = [];
  let databaseKey;
  const options = {
    records, origin: 'https://storage.test', crypto: webcrypto, locks: lockManager(),
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

test('unsupported wallet record versions are preserved and rejected before signing', async () => {
  const f = fixture();
  const record = JSON.stringify({ version: 999, address: 'owner-a' });
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

test('concurrent enrollment preserves the first envelope despite an OPFS lock failure', async () => {
  const f = fixture();
  let resumeSigning;
  let signingStarted;
  const started = new Promise(resolve => { signingStarted = resolve; });
  const pause = new Promise(resolve => { resumeSigning = resolve; });
  const sign = f.options.signMessage;
  f.options.signMessage = async (...args) => {
    signingStarted();
    await pause;
    return sign(...args);
  };
  let reads = 0;
  const read = f.options.records.getItem;
  f.options.records.getItem = name => { reads++; return read(name); };
  const first = openWalletStorage(f.options);
  await started;
  let secondSigned = false;
  const second = assert.rejects(openWalletStorage({ ...f.options,
    signMessage: async (...args) => { secondSigned = true; return sign(...args); },
    storage: { open: async () => { throw new Error('Another tab is using this database'); } },
  }), /Another tab/);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(reads, 1, 'the waiting tab must not read enrollment metadata yet');
  assert.equal(secondSigned, false);
  resumeSigning();
  await first;
  const saved = [...f.values.values()][0];
  await second;
  assert.equal(reads, 2);
  assert.equal([...f.values.values()][0], saved);
  assert.equal(f.signedAddresses.length, 3, 'only the first tab enrolls with two signatures');
  await openWalletStorage(f.options);
  assert.equal([...f.values.values()][0], saved);
  assert.equal(f.keys.length, 2, 'the original database reopens after the lock failure');
});

test('a rejected enrollment releases the lock for the next attempt', async () => {
  const f = fixture();
  await assert.rejects(openWalletStorage({ ...f.options,
    signMessage: async () => { throw new Error('User rejected'); },
  }), /User rejected/);
  assert.deepEqual(await openWalletStorage(f.options), { encrypted: true });
});

test('missing Web Locks fails before reading records or asking for signatures', async () => {
  const f = fixture();
  await assert.rejects(openWalletStorage({ ...f.options, locks: null,
    records: { getItem: () => assert.fail('must not read records without a lock') },
  }), /Web Locks are unavailable/);
  assert.equal(f.signedAddresses.length, 0);
  assert.equal(f.values.size, 0);
  assert.equal(f.keys.length, 0);
});

test('enrollment reconfirms an account changed in Freighter before binding storage', async () => {
  const f = fixture();
  let active = 'owner-a';
  const confirmations = [];
  f.options.getAddress = async () => active;
  f.options.confirmAccount = async details => {
    confirmations.push(details);
    assert.equal(f.signedAddresses.length, 0);
    assert.equal(f.values.size, 0);
    active = 'owner-b';
  };
  await openWalletStorage(f.options);
  assert.deepEqual(confirmations, [
    { address: 'owner-a', fresh: true },
    { address: 'owner-b', fresh: true },
  ]);
  assert.deepEqual(f.signedAddresses, ['owner-b', 'owner-b']);
  assert.equal(JSON.parse([...f.values.values()][0]).address, 'owner-b');
});

test('unlock confirmation names the enrolled account even after switching accounts', async () => {
  const f = fixture();
  await openWalletStorage(f.options);
  f.options.getAddress = async () => assert.fail('existing storage must use its enrolled account');
  const confirmations = [];
  f.options.confirmAccount = async details => { confirmations.push(details); };
  await openWalletStorage(f.options);
  assert.deepEqual(confirmations, [{ address: 'owner-a', fresh: false }]);
  assert.equal(f.signedAddresses.at(-1), 'owner-a');
});

test('enrollment uses the live account confirmed in the dialog without prompting twice', async () => {
  const f = fixture();
  let active = 'owner-a';
  let confirmations = 0;
  f.options.getAddress = async () => active;
  f.options.confirmAccount = async () => {
    confirmations++;
    active = 'owner-b';
    return active;
  };
  await openWalletStorage(f.options);
  assert.equal(confirmations, 1);
  assert.deepEqual(f.signedAddresses, ['owner-b', 'owner-b']);
  assert.equal(JSON.parse([...f.values.values()][0]).address, 'owner-b');
});

test('cancelling account confirmation never signs or changes storage', async () => {
  for (const existing of [false, true]) {
    const f = fixture();
    if (existing) await openWalletStorage(f.options);
    const saved = [...f.values];
    const signatures = f.signedAddresses.length;
    const opens = f.keys.length;
    f.options.confirmAccount = async () => {
      throw Object.assign(new Error('Storage unlock cancelled.'), { code: 'unlock-cancelled' });
    };
    await assert.rejects(openWalletStorage(f.options), { code: 'unlock-cancelled' });
    assert.deepEqual([...f.values], saved);
    assert.equal(f.signedAddresses.length, signatures);
    assert.equal(f.keys.length, opens);
  }
});

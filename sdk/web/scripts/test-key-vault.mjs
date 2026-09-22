import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseKeyVault } from '../js/key-vault.js';
import { MemoryKeyStore, fakeCredentials } from './key-vault-fixture.mjs';
const PASSWORD = 'synthetic correct horse battery';
const NEXT = 'synthetic different long password';
const id = 'spp.encrypted.db';
const bytes = session => session.keyProvider(id, 'open');
const rejected = (promise, code) => assert.rejects(promise, error => error.code === code);
function fixture() {
  const store = new MemoryKeyStore();
  const fake = fakeCredentials();
  return { store, ...fake, vault: new DatabaseKeyVault({ store, credentials: fake.credentials, origin: 'https://vault.test' }) };
}

test('random key persists wrapped, reopens identically, and locks explicitly', async () => {
  const { vault, store } = fixture();
  const session = await vault.createPassword(PASSWORD);
  const original = new Uint8Array(bytes(session));
  assert.equal(original.length, 32);
  const encoded = JSON.stringify(store.value);
  assert(!encoded.includes(PASSWORD));
  assert(!encoded.includes(Buffer.from(original).toString('base64url')));
  const reopened = await vault.unlockPassword(PASSWORD);
  assert.deepEqual(bytes(reopened), original);
  assert.throws(() => reopened.keyProvider('another.db', 'open'), { code: 'wrong-database' });
  const owned = bytes(session);
  session.lock();
  assert(owned.every(byte => byte === 0));
  assert.throws(() => bytes(session), { code: 'locked' });
  reopened.lock();
  const other = fixture();
  const different = await other.vault.createPassword(PASSWORD);
  assert.notDeepEqual(bytes(different), original);
  different.lock();
});

test('wrong password and duplicate creation do not mutate persistence', async () => {
  const { vault, store } = fixture();
  (await vault.createPassword(PASSWORD)).lock();
  const before = JSON.stringify(store.value);
  await rejected(vault.unlockPassword(NEXT), 'unlock-failed');
  await rejected(vault.createPassword(NEXT), 'already-exists');
  assert.equal(JSON.stringify(store.value), before);
  assert.equal(store.writes, 1);
});

test('missing key is never silently regenerated', async () => {
  const { vault, store } = fixture();
  await rejected(vault.unlockPassword(PASSWORD), 'missing-key');
  await rejected(vault.unlockPasskey(), 'missing-key');
  assert.equal(store.writes, 0);
});

test('password change rewraps the same data key and rejects the old password', async () => {
  const { vault, store } = fixture();
  const session = await vault.createPassword(PASSWORD);
  const original = new Uint8Array(bytes(session)); session.lock();
  const old = structuredClone(store.value);
  await vault.changePassword(PASSWORD, NEXT);
  const reopened = await vault.unlockPassword(NEXT);
  assert.deepEqual(bytes(reopened), original); reopened.lock();
  assert.notEqual(store.value.password.salt, old.password.salt);
  assert.notEqual(store.value.password.iv, old.password.iv);
  await rejected(vault.unlockPassword(PASSWORD), 'unlock-failed');
});

test('tampered ciphertext, salt, identity and work factor fail closed', async () => {
  const { vault, store } = fixture();
  (await vault.createPassword(PASSWORD)).lock();
  const original = structuredClone(store.value);
  for (const mutate of [
    r => { r.password.ciphertext = 'A'.repeat(64); },
    r => { r.password.salt = 'A'.repeat(43); },
    r => { r.vaultId = 'A'.repeat(22); },
    r => { r.databaseId = 'other'; },
    r => { r.version = 2; },
    r => { r.password.iterations = 1; },
    r => { r.password.iterations = 1e12; },
    r => { r.password.extra = true; },
  ]) {
    store.value = structuredClone(original); mutate(store.value);
    const before = JSON.stringify(store.value);
    await assert.rejects(vault.unlockPassword(PASSWORD));
    assert.equal(JSON.stringify(store.value), before);
  }
});

test('storage write failure leaves the old password usable', async () => {
  const { vault, store } = fixture();
  (await vault.createPassword(PASSWORD)).lock();
  const before = JSON.stringify(store.value);
  store.failWrites = true;
  await assert.rejects(vault.changePassword(PASSWORD, NEXT), /storage failure/);
  assert.equal(JSON.stringify(store.value), before);
  (await vault.unlockPassword(PASSWORD)).lock();
});

test('concurrent creation yields one durable key; concurrent rewrap does not lose updates', async () => {
  const { vault, store } = fixture();
  const created = await Promise.allSettled([vault.createPassword(PASSWORD), vault.createPassword(PASSWORD)]);
  assert.equal(created.filter(r => r.status === 'fulfilled').length, 1);
  created.find(r => r.status === 'fulfilled').value.lock();
  const results = await Promise.allSettled([vault.changePassword(PASSWORD, NEXT), vault.changePassword(PASSWORD, NEXT)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(store.value.revision, 2);
  (await vault.unlockPassword(NEXT)).lock();
});

test('passkey and password unwrap the same key, including password recovery', async () => {
  const { vault, state, store } = fixture();
  const session = await vault.createPassword(PASSWORD);
  const original = new Uint8Array(bytes(session)); session.lock();
  await vault.addPasskey(PASSWORD);
  assert.equal(state.creates, 1);
  assert.equal(state.gets, 1);
  const unlocked = await vault.unlockPasskey();
  assert.deepEqual(bytes(unlocked), original); unlocked.lock();
  assert.equal(state.gets, 2); // Re-evaluates PRF; no cached secret/signature reuse.
  await vault.resetPasswordWithPasskey(NEXT);
  const recovered = await vault.unlockPassword(NEXT);
  assert.deepEqual(bytes(recovered), original); recovered.lock();
  await rejected(vault.unlockPassword(PASSWORD), 'unlock-failed');
  const priorPasskey = store.value.passkey;
  await vault.changePassword(NEXT, PASSWORD);
  assert.deepEqual(store.value.passkey, priorPasskey);
  await vault.removePasskey(PASSWORD);
  await rejected(vault.unlockPasskey(), 'missing-passkey');
  (await vault.unlockPassword(PASSWORD)).lock();
});

for (const fault of ['unsupported-create', 'unsupported-get', 'cancel-create', 'cancel-get', 'origin', 'challenge', 'cross-origin', 'credential', 'no-uv', 'rp-hash']) {
  test(`passkey ${fault} refuses enrollment and preserves password access`, async () => {
    const { vault, store, state } = fixture();
    (await vault.createPassword(PASSWORD)).lock();
    const before = JSON.stringify(store.value);
    state.fault = fault;
    await assert.rejects(vault.addPasskey(PASSWORD));
    assert.equal(JSON.stringify(store.value), before);
    (await vault.unlockPassword(PASSWORD)).lock();
  });
}

test('different PRF secret cannot decrypt and does not alter the envelope', async () => {
  const { vault, store, state } = fixture();
  (await vault.createPassword(PASSWORD)).lock();
  await vault.addPasskey(PASSWORD);
  const before = JSON.stringify(store.value);
  state.fault = 'different-secret';
  await rejected(vault.unlockPasskey(), 'unlock-failed');
  assert.equal(JSON.stringify(store.value), before);
});

test('passkey is bound to origin before requesting the credential', async () => {
  const { vault, store, credentials, state } = fixture();
  (await vault.createPassword(PASSWORD)).lock(); await vault.addPasskey(PASSWORD);
  const other = new DatabaseKeyVault({ store, credentials, origin: 'https://other.test' });
  const before = state.gets;
  await rejected(other.unlockPasskey(), 'wrong-origin');
  assert.equal(state.gets, before);
});

test('reject weak creation passwords but preserve spaces and unicode exactly', async () => {
  const { vault } = fixture();
  await rejected(vault.createPassword('short'), 'invalid-password');
  const password = '  Synthetic café 🔐 passphrase  ';
  (await vault.createPassword(password)).lock();
  (await vault.unlockPassword(password)).lock();
  await rejected(vault.unlockPassword(password.trim()), 'unlock-failed');
});

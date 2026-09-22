import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseKeyVault } from '../js/key-vault.js';
import { MemoryKeyStore, createWalletSigner } from './key-vault-fixture.mjs';
import { createBackup, decryptBackup, readBackup } from '../../../app/js/database-backup.js';
const password = 'synthetic wallet recovery password';
const key = session => new Uint8Array(session.keyProvider('spp.encrypted.db', 'open'));
async function fixture() {
  const store = new MemoryKeyStore();
  const vault = new DatabaseKeyVault({ store, origin: 'https://vault.test' });
  const initial = await vault.createPassword(password);
  const expected = key(initial); initial.lock();
  return { store, vault, expected, ...await createWalletSigner() };
}
test('wallet wraps existing random key, verifies repeatable signatures and preserves password and backup recovery', async () => {
  const f = await fixture(); const old = structuredClone(f.store.value);
  await f.vault.addWallet(password, f.signer);
  assert.equal(f.state.calls.length, 2);
  assert.equal(f.state.calls[0].message, f.state.calls[1].message);
  assert.match(f.state.calls[0].message, /spp\/database-key-wrap\/v1\/wallet-signature/);
  assert.match(f.state.calls[0].message, /https:\/\/vault.test/);
  assert.equal(f.state.calls[0].options.address, f.address);
  assert.deepEqual(f.store.value.password, old.password);
  let session = await f.vault.unlockWallet(f.signer);
  assert.deepEqual(key(session), f.expected); session.lock();
  f.state.fault = 'hex'; session = await f.vault.unlockWallet(f.signer);
  assert.deepEqual(key(session), f.expected); session.lock(); f.state.fault = null;
  const restored = new DatabaseKeyVault({ store: { read: async () => structuredClone(f.store.value) }, origin: 'https://vault.test' });
  session = await restored.unlockWallet(f.signer); assert.deepEqual(key(session), f.expected); session.lock();
  session = await f.vault.unlockWallet(f.signer);
  const snapshot = crypto.getRandomValues(new Uint8Array(512));
  const archive = await createBackup(f.store.value, snapshot, session.keyProvider);
  session.lock();
  const backupVault = new DatabaseKeyVault({ store: { read: async () => readBackup(archive).record }, origin: 'https://vault.test' });
  session = await backupVault.unlockPassword(password);
  assert.deepEqual(await decryptBackup(archive, session.keyProvider), snapshot); session.lock();
  session = await backupVault.unlockWallet(f.signer);
  assert.deepEqual(await decryptBackup(archive, session.keyProvider), snapshot); session.lock();
  const legacy = new DatabaseKeyVault({ store: { read: async () => old }, origin: 'https://vault.test' });
  session = await legacy.unlockPassword(password); assert.deepEqual(key(session), f.expected); session.lock();
  await f.vault.changePassword(password, 'replacement wallet recovery password');
  session = await f.vault.unlockWallet(f.signer); assert.deepEqual(key(session), f.expected); session.lock();
  await f.vault.removeWallet('replacement wallet recovery password');
  await assert.rejects(f.vault.unlockWallet(f.signer), e => e.code === 'missing-wallet');
});
test('wrong account, origin, signature, cancellation and tampered metadata never change stored envelopes', async () => {
  const f = await fixture();
  for (const fault of ['account', 'reported-account', 'signature', 'cancel']) {
    f.state.fault = fault; const before = structuredClone(f.store.value);
    await assert.rejects(f.vault.addWallet(password, f.signer));
    assert.deepEqual(f.store.value, before);
  }
  f.state.fault = null; await f.vault.addWallet(password, f.signer);
  for (const fault of ['account', 'reported-account', 'signature', 'cancel']) {
    f.state.fault = fault; const before = structuredClone(f.store.value);
    await assert.rejects(f.vault.unlockWallet(f.signer));
    assert.deepEqual(f.store.value, before);
  }
  f.state.fault = null;
  await assert.rejects(new DatabaseKeyVault({ store: f.store, origin: 'https://other.test' }).unlockWallet(f.signer), e => e.code === 'wrong-origin');
  f.store.value.wallet.salt = 'A'.repeat(43);
  await assert.rejects(f.vault.unlockWallet(f.signer));
  const session = await f.vault.unlockPassword(password); assert.deepEqual(key(session), f.expected); session.lock();
});
test('second enrollment request must succeed before commit', async () => {
  const f = await fixture(); const before = structuredClone(f.store.value);
  const original = f.signer.signMessage; let count = 0;
  f.signer.signMessage = (...args) => { if (++count === 2) f.state.fault = 'cancel'; return original(...args); };
  await assert.rejects(f.vault.addWallet(password, f.signer));
  assert.deepEqual(f.store.value, before);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { Keypair } from '@stellar/stellar-sdk';
import { exposeSigner } from '../../src/testAccount.mjs';
import { openWalletStorage } from '../../../app/js/storage-key.js';

async function signerBridge(keypair) {
  const callbacks = {};
  const names = await exposeSigner({
    exposeFunction: async (name, callback) => { callbacks[name] = callback; },
  }, keypair);
  return {
    signMessage: callbacks[names.signMsgName],
    verifySignature: (address, message, signature) =>
      callbacks[names.verifyMsgName](address, message, Array.from(signature)),
  };
}

test('E2E account signatures create and reopen the production wallet storage envelope', async () => {
  const account = Keypair.random();
  const signer = await signerBridge(account);
  const values = new Map();
  let databaseKey;
  let opens = 0;
  const options = {
    ...signer,
    getAddress: async () => account.publicKey(),
    origin: 'http://localhost:8080',
    crypto: webcrypto,
    locks: { request: async (_name, _options, callback) => callback() },
    records: {
      getItem: key => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
    },
    storage: { open: async ({ keyProvider, createNew }) => {
      const key = await keyProvider();
      assert.equal(createNew, opens === 0);
      if (opens === 0) databaseKey = key.slice();
      else assert.deepEqual(key, databaseKey);
      opens++;
      return { encrypted: true };
    } },
  };
  await openWalletStorage(options);
  const record = [...values.values()][0];
  // Simulate reloading with a new bridge for the same Stellar identity.
  await openWalletStorage({ ...options, ...await signerBridge(account) });
  assert.equal(opens, 2);
  assert.equal([...values.values()][0], record);
  assert.equal(JSON.parse(record).address, account.publicKey());

  await assert.rejects(openWalletStorage({ ...options,
    signMessage: async (...args) => {
      const signed = await signer.signMessage(...args);
      const bytes = Buffer.from(signed.signedMessage, 'base64');
      bytes[0] ^= 1;
      return { ...signed, signedMessage: bytes.toString('base64') };
    },
  }), /Invalid wallet signature/);
  assert.equal(opens, 2);
  assert.equal([...values.values()][0], record);
});

test('E2E message verification rejects a different message or account', async () => {
  const account = Keypair.random();
  const other = Keypair.random();
  const signer = await signerBridge(account);
  const { signedMessage, signerAddress } = await signer.signMessage('unlock', { address: account.publicKey() });
  const signature = Buffer.from(signedMessage, 'base64');
  assert.equal(signerAddress, account.publicKey());
  assert.equal(await signer.verifySignature(account.publicKey(), 'unlock', signature), true);
  assert.equal(await signer.verifySignature(account.publicKey(), 'different', signature), false);
  assert.equal(await signer.verifySignature(other.publicKey(), 'unlock', signature), false);
  assert.throws(() => signer.signMessage('unlock', { address: other.publicKey() }), /different account/);
});

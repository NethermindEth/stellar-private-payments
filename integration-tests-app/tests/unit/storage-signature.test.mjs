import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, webcrypto } from 'node:crypto';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { verifyStorageSignature } from '../../../app/js/storage-signature.js';

test('storage verification accepts real Stellar signatures and rejects altered messages', async () => {
  const account = Keypair.random();
  const key = StrKey.decodeEd25519PublicKey(account.publicKey());
  const message = 'unlock local storage';
  const digest = createHash('sha256').update(`Stellar Signed Message:\n${message}`).digest();
  const signature = account.sign(digest);
  assert.equal(await verifyStorageSignature(key, message, signature, webcrypto), true);
  assert.equal(await verifyStorageSignature(key, 'different message', signature, webcrypto), false);
});

test('unsupported Ed25519 import or verification gives a browser-update message', async () => {
  for (const failingMethod of ['importKey', 'verify']) {
    const cause = new DOMException('Unrecognized algorithm name', 'NotSupportedError');
    const subtle = {
      importKey: async () => ({}),
      digest: async () => new Uint8Array(32),
      verify: async () => true,
      [failingMethod]: async () => { throw cause; },
    };
    await assert.rejects(verifyStorageSignature(new Uint8Array(32), 'unlock', new Uint8Array(64), { subtle }), error => {
      assert.match(error.message, /Update your browser to the latest version and try again/);
      assert.equal(error.cause, cause);
      return true;
    });
  }
});

test('other verification errors are preserved instead of blaming browser support', async () => {
  const cause = new DOMException('Invalid key', 'DataError');
  await assert.rejects(verifyStorageSignature(new Uint8Array(32), 'unlock', new Uint8Array(64), {
    subtle: { importKey: async () => { throw cause; } },
  }), error => error === cause);
});

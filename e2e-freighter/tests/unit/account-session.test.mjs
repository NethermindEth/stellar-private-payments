import assert from 'node:assert/strict';
import test from 'node:test';

import {
  accountSession,
  forgetNoteOwner,
  rememberNoteOwner,
  rememberedNoteOwner,
} from '../../../app/js/account-session.js';

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const SIGNER = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
const PASSPHRASE = 'Test SDF Network ; September 2015';

// Today's behaviour: nothing can choose a signing account, so the owner signs.
test('with no signing account chosen, the owner signs for itself', () => {
  assert.deepEqual(
    accountSession({ networkPassphrase: PASSPHRASE, address: OWNER, signingAddress: null }),
    { networkPassphrase: PASSPHRASE, userAddress: OWNER, signerAddress: OWNER },
  );
});

test('a session state naming a signing account passes it through as the signer', () => {
  assert.deepEqual(
    accountSession({ networkPassphrase: PASSPHRASE, address: OWNER, signingAddress: SIGNER }),
    { networkPassphrase: PASSPHRASE, userAddress: OWNER, signerAddress: SIGNER },
  );
});

// A disconnected session has neither, and must not turn `undefined` into a
// signer the facade would then compare against.
test('a disconnected session names no account at all', () => {
  assert.deepEqual(
    accountSession(),
    { networkPassphrase: null, userAddress: null, signerAddress: null },
  );
});

function memoryStorage() {
  const items = new Map();
  return {
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
    removeItem: (key) => items.delete(key),
  };
}

// Signing as another account makes it Freighter's active one, so the owner
// has to outlive that: it is remembered until the user disconnects.
test('the connected owner is remembered until forgotten', () => {
  const storage = memoryStorage();
  assert.equal(rememberedNoteOwner(storage), null);
  rememberNoteOwner(OWNER, storage);
  assert.equal(rememberedNoteOwner(storage), OWNER);
  forgetNoteOwner(storage);
  assert.equal(rememberedNoteOwner(storage), null);
});

test('storage that cannot be read remembers no owner', () => {
  const broken = { getItem: () => { throw new Error('blocked'); } };
  assert.equal(rememberedNoteOwner(broken), null);
});

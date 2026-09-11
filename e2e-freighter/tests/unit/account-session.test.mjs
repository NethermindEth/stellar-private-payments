import assert from 'node:assert/strict';
import test from 'node:test';

import { accountSession } from '../../../app/js/account-session.js';

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

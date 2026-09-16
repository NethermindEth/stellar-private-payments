import assert from 'node:assert/strict';
import test from 'node:test';

import {
  addSigner,
  chosenSigner,
  withdrawalLinksAccounts,
} from '../../../app/js/signing-account.js';
import { getTransactionErrorMessage } from '../../../app/js/ui/errors.js';

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const SIGNER = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
const STRANGER = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ';

test('a chosen signer is remembered once, and the owner never is', () => {
  let signers = addSigner([], SIGNER, OWNER);
  signers = addSigner(signers, SIGNER, OWNER);
  signers = addSigner(signers, OWNER, OWNER);
  assert.deepEqual(signers, [SIGNER]);
});

test('the owner signs unless an account chosen this session is picked', () => {
  assert.equal(chosenSigner({ selected: OWNER, owner: OWNER, signers: [SIGNER] }), OWNER);
  assert.equal(chosenSigner({ selected: SIGNER, owner: OWNER, signers: [SIGNER] }), SIGNER);
  assert.equal(chosenSigner({ selected: null, owner: OWNER, signers: [SIGNER] }), OWNER);
});

// A value that is not in the session's list (a signer from before a reconnect)
// must not sign; the owner does.
test('a picked account that was never chosen this session does not sign', () => {
  assert.equal(chosenSigner({ selected: STRANGER, owner: OWNER, signers: [SIGNER] }), OWNER);
  assert.equal(chosenSigner({ selected: SIGNER, owner: OWNER, signers: [] }), OWNER);
});

test('a withdrawal to the owner signed by another account links the two', () => {
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: SIGNER, recipient: OWNER }), true);
});

test('no link when the owner signs, or the recipient is someone else', () => {
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: OWNER, recipient: OWNER }), false);
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: SIGNER, recipient: STRANGER }), false);
});


test('a signature from another account says the chosen account is not in Freighter', () => {
  const messages = [
    // sdk/web/src/signer.rs, which signs the app's transactions
    `signer.signTransaction: wallet signed as ${OWNER}, not the requested ${SIGNER}`,
    // app/js/wallet-signer-guard.js
    'signTransaction: the wallet signed with a different account than the one requested.',
  ];
  for (const message of messages) {
    assert.match(getTransactionErrorMessage(new Error(message), 'Deposit'), /isn't in Freighter/);
  }
});

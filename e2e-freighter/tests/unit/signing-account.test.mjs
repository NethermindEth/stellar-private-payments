import assert from 'node:assert/strict';
import test from 'node:test';

import {
  activeSuggestion,
  addSigner,
  chosenSigner,
  rememberSigners,
  rememberedSigners,
  removeSigner,
  signingPrivacyWarning,
  withdrawalLinksAccounts,
} from '../../../app/js/signing-account.js';
import { getTransactionErrorMessage } from '../../../app/js/ui/errors.js';

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const SIGNER = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
const STRANGER = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ';

test('signing with the deposit account warns independently of the recipient', () => {
  assert.match(signingPrivacyWarning({ owner: OWNER, signer: OWNER }), /Signing with your deposit account can link this transaction/);
  assert.equal(signingPrivacyWarning({ owner: OWNER, signer: SIGNER }), '');
  assert.equal(signingPrivacyWarning({ owner: OWNER, signer: null }), '');
  assert.equal(signingPrivacyWarning({ owner: null, signer: null }), '');
});

test('a chosen signer is remembered once, and the owner never is', () => {
  let signers = addSigner([], SIGNER, OWNER);
  signers = addSigner(signers, SIGNER, OWNER);
  signers = addSigner(signers, OWNER, OWNER);
  assert.deepEqual(signers, [SIGNER]);
});

test('the owner or another signer must be explicitly selected', () => {
  assert.equal(chosenSigner({ selected: OWNER, owner: OWNER, signers: [SIGNER] }), OWNER);
  assert.equal(chosenSigner({ selected: SIGNER, owner: OWNER, signers: [SIGNER] }), SIGNER);
  assert.equal(chosenSigner({ selected: null, owner: OWNER, signers: [SIGNER] }), null);
});

// A value that is not in the session's list (a signer from before a reconnect)
// must not sign; the user must choose again.
test('a picked account that was never chosen this session does not sign', () => {
  assert.equal(chosenSigner({ selected: STRANGER, owner: OWNER, signers: [SIGNER] }), null);
  assert.equal(chosenSigner({ selected: SIGNER, owner: OWNER, signers: [] }), null);
});

test('a withdrawal to the owner signed by another account links the two', () => {
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: SIGNER, recipient: OWNER }), true);
});

test('a withdrawal warns when owner, signer, and recipient are the same account', () => {
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: OWNER, recipient: OWNER }), true);
});

test('no owner-recipient warning when the recipient is someone else', () => {
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: OWNER, recipient: STRANGER }), false);
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: SIGNER, recipient: STRANGER }), false);
});

test('incomplete withdrawal accounts do not trigger a warning', () => {
  assert.equal(withdrawalLinksAccounts({ owner: null, signer: SIGNER, recipient: null }), false);
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: null, recipient: OWNER }), false);
  assert.equal(withdrawalLinksAccounts({ owner: OWNER, signer: OWNER, recipient: null }), false);
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

function memoryStorage() {
  const items = new Map();
  return {
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
  };
}

test('accounts added to sign are remembered per owner', () => {
  const storage = memoryStorage();
  rememberSigners(OWNER, [SIGNER, STRANGER], storage);
  assert.deepEqual(rememberedSigners(OWNER, storage), [SIGNER, STRANGER]);
  assert.deepEqual(rememberedSigners(SIGNER, storage), []);
  assert.deepEqual(rememberedSigners(null, storage), []);
});

test('a tampered or unreadable list remembers only distinct accounts other than the owner', () => {
  const storage = memoryStorage();
  storage.setItem(`poolstellar_signers:${OWNER}`, JSON.stringify([SIGNER, OWNER, 7, SIGNER]));
  assert.deepEqual(rememberedSigners(OWNER, storage), [SIGNER]);
  storage.setItem(`poolstellar_signers:${OWNER}`, '{not json');
  assert.deepEqual(rememberedSigners(OWNER, storage), []);
  assert.deepEqual(rememberedSigners(OWNER, { getItem: () => { throw new Error('blocked'); } }), []);
});

test('removing an account keeps the others in order', () => {
  assert.deepEqual(removeSigner([SIGNER, STRANGER], SIGNER), [STRANGER]);
  assert.deepEqual(removeSigner([STRANGER], SIGNER), [STRANGER]);
});

test('Freighter\'s active account is offered only when it is new to the picker', () => {
  assert.equal(activeSuggestion({ active: STRANGER, owner: OWNER, signers: [SIGNER] }), STRANGER);
  assert.equal(activeSuggestion({ active: OWNER, owner: OWNER, signers: [SIGNER] }), null);
  assert.equal(activeSuggestion({ active: SIGNER, owner: OWNER, signers: [SIGNER] }), null);
  // Freighter keeping its account from the site, or no wallet connected.
  assert.equal(activeSuggestion({ active: '', owner: OWNER, signers: [] }), null);
  assert.equal(activeSuggestion({ active: STRANGER, owner: null, signers: [] }), null);
});

test('the offered active account signs only while Freighter still has it active', () => {
  assert.equal(chosenSigner({ selected: STRANGER, owner: OWNER, signers: [], active: STRANGER }), STRANGER);
  assert.equal(chosenSigner({ selected: STRANGER, owner: OWNER, signers: [], active: SIGNER }), null);
  assert.equal(chosenSigner({ selected: STRANGER, owner: OWNER, signers: [], active: '' }), null);
});

test('empty or disconnected signer selections require a new choice', () => {
  assert.equal(chosenSigner({ selected: '', owner: OWNER, signers: [SIGNER] }), null);
  assert.equal(chosenSigner({ selected: SIGNER, owner: null, signers: [SIGNER] }), null);
});

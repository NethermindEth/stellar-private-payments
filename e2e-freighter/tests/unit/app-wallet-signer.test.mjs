import assert from 'node:assert/strict';
import test from 'node:test';

import { verifySignerAddress } from '../../../app/js/wallet-signer-guard.js';

const REQUESTED = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const SUBSTITUTED = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';

test('a wallet reporting the requested account is accepted', () => {
  assert.doesNotThrow(() => verifySignerAddress('signTransaction', REQUESTED, REQUESTED));
});

// Freighter returns success with signerAddress set to whichever account was
// active when it does not hold the requested one, with nothing in the approval
// prompt naming the address that was asked for.
test('a wallet reporting a substituted account is refused', () => {
  assert.throws(
    () => verifySignerAddress('signTransaction', REQUESTED, SUBSTITUTED),
    (error) => {
      assert.equal(error.code, 'SIGNER_ADDRESS_MISMATCH');
      assert.match(error.message, /signTransaction/);
      return true;
    },
  );
});

test('the refusal leaks neither address', () => {
  try {
    verifySignerAddress('signAuthEntry', REQUESTED, SUBSTITUTED);
    assert.fail('expected a refusal');
  } catch (error) {
    assert.ok(!error.message.includes(REQUESTED), error.message);
    assert.ok(!error.message.includes(SUBSTITUTED), error.message);
  }
});

// normalizeWalletError's classifier substring-matches these words to decide a
// signing failure was the user's choice; a substitution is not.
test('the refusal does not read as a user cancellation', () => {
  try {
    verifySignerAddress('signMessage', REQUESTED, SUBSTITUTED);
    assert.fail('expected a refusal');
  } catch (error) {
    const message = error.message.toLowerCase();
    for (const word of ['rejected', 'denied', 'cancelled']) {
      assert.ok(!message.includes(word), `'${word}' in: ${error.message}`);
    }
  }
});

test('nothing to compare is not a failure', () => {
  assert.doesNotThrow(() => verifySignerAddress('signTransaction', undefined, SUBSTITUTED));
  assert.doesNotThrow(() => verifySignerAddress('signTransaction', REQUESTED, undefined));
});

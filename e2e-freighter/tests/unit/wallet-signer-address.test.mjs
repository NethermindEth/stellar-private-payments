// Unit coverage for verifySignerAddress, the JavaScript counterpart to
// sdk/web/src/signer.rs's check: a wallet must not be allowed to sign with an
// account other than the one requested.
//
// Imported directly rather than via wallet.js, which does not load under plain
// `node --test`.

import assert from 'node:assert/strict';
import test from 'node:test';

import { verifySignerAddress as verifyAppSide } from '../../../app/js/wallet-signer-guard.js';
import { verifySignerAddress as verifySdkSide } from '../../../sdk/web/js/signer-guard.js';

const REQUESTED = 'GDZONBLK4NS2Z3VQZME6N4BGHMEYCLXSLUJ4HVTKX77TSHWRTFKIFP4B';
const OTHER = 'GCOLXNSUPANEQCSN44FJ7RTVGUQQFXMAZGA3BUZ7Q7FK7O6HUN52M2NC';

for (const [label, verifySignerAddress] of [['app/js', verifyAppSide], ['sdk/web/js', verifySdkSide]]) {
  test(`${label}: verifySignerAddress accepts a matching signer address`, () => {
    assert.doesNotThrow(() => verifySignerAddress('Transaction signature', REQUESTED, REQUESTED));
  });

  test(`${label}: verifySignerAddress rejects a mismatching signer address`, () => {
    assert.throws(
      () => verifySignerAddress('Transaction signature', REQUESTED, OTHER),
      (error) => {
        assert.equal(error.code, 'SIGNER_ADDRESS_MISMATCH');
        assert.match(error.message, new RegExp(`wallet signed with ${OTHER}, but ${REQUESTED} was requested`));
        // The rejection must be classifiable as something other than a user
        // decline -- a wrong signer is not the user saying no.
        assert.notEqual(error.code, 'USER_REJECTED');
        assert.notEqual(error.code, -4);
        assert.doesNotMatch(error.message.toLowerCase(), /reject|declin|denied|cancel/);
        return true;
      },
    );
  });

  test(`${label}: verifySignerAddress skips silently when no address was requested`, () => {
    // The realistic no-requested-address case: app/js/wallet.js's
    // signWalletMessage has no production caller passing opts.address today
    // so a mismatch cannot be detected there --
    // this must not become a vacuous throw-on-nothing check.
    assert.doesNotThrow(() => verifySignerAddress('Message signature', undefined, OTHER));
    assert.doesNotThrow(() => verifySignerAddress('Message signature', null, OTHER));
    assert.doesNotThrow(() => verifySignerAddress('Message signature', '', OTHER));
  });

  test(`${label}: verifySignerAddress skips silently when the wallet reports no signer address`, () => {
    // A non-SEP-43-compliant custom signer might omit signerAddress
    // entirely; absence of the field to check is not evidence of a mismatch.
    assert.doesNotThrow(() => verifySignerAddress('Auth entry signature', REQUESTED, undefined));
    assert.doesNotThrow(() => verifySignerAddress('Auth entry signature', REQUESTED, null));
  });
}

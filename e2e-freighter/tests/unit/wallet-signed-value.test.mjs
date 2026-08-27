// Unit coverage for assertSignedValue: a wallet that returns neither an error
// payload nor a signature (older Freighter's decline) must not yield an
// undefined signed value to the caller.
//
// Two copies exist by design. app/js/wallet-signer-guard.js uses the string
// 'USER_REJECTED', matching wallet.js's own convention; sdk/web/js/signer-guard.js
// uses the numeric -4, matching freighter.js's. errors.js's isUserCancelledError
// accepts both.
//
// Imported directly rather than via wallet.js/freighter.js, which do not load
// under plain `node --test`.

import assert from 'node:assert/strict';
import test from 'node:test';

import { assertSignedValue as assertAppSide } from '../../../app/js/wallet-signer-guard.js';
import { assertSignedValue as assertSdkSide } from '../../../sdk/web/js/signer-guard.js';

const CASES = [
  ['app/js', assertAppSide, 'USER_REJECTED'],
  ['sdk/web/js', assertSdkSide, -4],
];

for (const [label, assertSignedValue, expectedCode] of CASES) {
  test(`${label}: assertSignedValue does nothing when the value is present`, () => {
    assert.doesNotThrow(() => assertSignedValue('should not be seen', 'signed-xdr'));
  });

  for (const [valueLabel, value] of [['null', null], ['undefined', undefined], ['empty string', '']]) {
    test(`${label}: assertSignedValue rejects a ${valueLabel} value as code ${expectedCode}`, () => {
      assert.throws(
        () => assertSignedValue('No signed transaction returned by the wallet.', value),
        (error) => {
          assert.equal(error.code, expectedCode);
          assert.equal(error.message, 'No signed transaction returned by the wallet.');
          return true;
        },
      );
    });
  }
}

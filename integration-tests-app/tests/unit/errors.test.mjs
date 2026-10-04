import assert from 'node:assert/strict';
import test from 'node:test';

import { getFriendlyErrorMessage } from '../../../app/js/ui/errors.js';

const REFUSED_DEPOSIT =
  'simulate transaction: transaction simulation failed: HostError: Error(Contract, #18)';

test('a deposit refused by a paused pool says deposits are paused', () => {
  assert.equal(
    getFriendlyErrorMessage(new Error(REFUSED_DEPOSIT), 'Deposit'),
    'Deposits into this pool are paused. Withdrawals and transfers still work.',
  );
});

test('a deposit the SDK refuses before proving says deposits are paused', () => {
  assert.equal(
    getFriendlyErrorMessage(new Error('deposits into pool CPOOL are paused'), 'Deposit'),
    'Deposits into this pool are paused. Withdrawals and transfers still work.',
  );
});

test('an unpause of an open pool says deposits are not paused', () => {
  assert.equal(
    getFriendlyErrorMessage(new Error(REFUSED_DEPOSIT.replace('#18', '#19'))),
    'Deposits into this pool are not paused.',
  );
});

test('an unknown root still says the pool state changed', () => {
  assert.equal(
    getFriendlyErrorMessage(new Error(REFUSED_DEPOSIT.replace('#18', '#8')), 'Withdraw'),
    'Pool state has changed. Please wait for sync to complete and try again.',
  );
});

test('a pool re-pointed to an allowlist the manifest does not name asks for a reload', () => {
  const unnamed =
    'fetch chain context: pool CPOOL reads the allowlist CTREE, which the deployment manifest ' +
    'does not name: add it to added_asp_memberships with its deployment ledger';
  assert.equal(
    getFriendlyErrorMessage(new Error(unnamed), 'Withdraw'),
    'This pool now uses an allowlist this version of the app does not know. Reload the page. If that does not help, the operator has not published the updated deployment yet.',
  );
});

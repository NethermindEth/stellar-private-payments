import assert from 'node:assert/strict';
import test from 'node:test';

import { describeError, describeRegistrationError, getFriendlyErrorMessage, UserFacingError } from '../../../app/js/ui/errors.js';

const REFUSED_DEPOSIT =
  'simulate transaction: transaction simulation failed: HostError: Error(Contract, #18)';

test('a deposit refused by a paused pool says deposits are paused', () => {
  assert.equal(
    getFriendlyErrorMessage(new Error(REFUSED_DEPOSIT), 'Deposit'),
    'Deposits into this pool are paused. Withdrawals and transfers still work.',
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

test('an internal error that mentions fetching is not called a network error', () => {
  const internal = 'fetch pool state: missing required contract keys for CPOOL: ["Admin", "State"]';
  for (const raw of [internal, 'storage timeout: worker did not answer', 'connection to the prover worker closed']) {
    const described = describeError(new Error(raw), 'Deposit');
    assert.equal(described.kind, 'unknown', raw);
    assert.equal(described.message, 'Deposit failed. Something went wrong.');
    assert.equal(described.details, raw);
  }
});

test('the SDK and browser network failures are network errors, with the raw text kept', () => {
  for (const raw of [
    'fetch pool state: network error: error sending request for url (https://rpc.example)',
    'RPC request timed out',
    'Failed to fetch',
    'NetworkError when attempting to fetch resource.',
    'Load failed',
  ]) {
    const described = describeError(new TypeError(raw), 'Deposit');
    assert.equal(described.kind, 'network', raw);
    assert.match(described.message, /^Network error\./);
    assert.equal(described.details, raw);
  }
});

test('a contract code past the simulation wording gets its own message', () => {
  const raw = 'transaction simulation failed: HostError: Error(Contract, #24)';
  assert.equal(getFriendlyErrorMessage(new Error(raw), 'Withdraw'), 'The pool does not pay itself or its token contract. Choose another recipient.');
  const other = describeError(new Error(raw.replace('#24', '#6')), 'Withdraw');
  assert.equal(other.message, 'The network rejected the transaction when it was tested, so nothing was sent.');
  assert.equal(other.details, raw.replace('#24', '#6'));
});

test('a spent note is not called a double-spend attempt', () => {
  const message = getFriendlyErrorMessage(new Error('HostError: Error(Contract, #9)'), 'Transfer');
  assert.match(message, /already been spent/);
  assert.doesNotMatch(message, /double-spend/i);
});

test('a user-facing error is shown as written, not as a failure', () => {
  const described = describeError(new UserFacingError('Enter a deposit amount'), 'Deposit');
  assert.deepEqual(described, { kind: 'user', message: 'Enter a deposit amount', details: '' });
});

test('a wallet rejection is a cancellation without details', () => {
  assert.deepEqual(describeError({ message: 'whatever', code: -4 }, 'Withdraw'), { kind: 'cancelled', message: 'Withdraw cancelled.', details: '' });
  assert.equal(describeRegistrationError({ code: -4 }).message, 'Registration cancelled.');
});

test('insufficient funds do not assume the pool token is XLM', () => {
  const message = getFriendlyErrorMessage(new Error('transaction failed: txINSUFFICIENT_BALANCE'), 'Deposit');
  assert.match(message, /pool's token/);
  assert.doesNotMatch(message, /enough XLM to cover/);
});

test('ASP membership problems name the Association Set Provider', () => {
  assert.match(getFriendlyErrorMessage(new Error('membership leaf not found'), 'Transfer'), /Association Set Provider/);
});

test('known SDK messages are reworded for the user', () => {
  assert.match(getFriendlyErrorMessage(new Error('register at ASP before transacting'), 'Deposit'), /not registered with the Association Set Provider/);
  assert.equal(getFriendlyErrorMessage(new Error('indexer sync in progress; try again shortly'), 'Deposit'), 'Still syncing with the network. Try again in a moment.');
  const notQueued = 'the RPC did not queue transaction abc (TRY_AGAIN_LATER); a copy sent earlier may still land, otherwise send it again';
  assert.match(getFriendlyErrorMessage(new Error(notQueued), 'Withdraw'), /check your balance before you send it again/);
  assert.equal(getFriendlyErrorMessage(new Error('Runtime not initialized. Call initializeRuntime first.'), 'Deposit'), 'Still connecting. Please wait a moment and try again.');
});

test('a registration the registry refuses keeps its registry message and raw text', () => {
  const raw = 'HostError: Error(Contract, #5)';
  const described = describeRegistrationError(new Error(raw));
  assert.match(described.message, /already registered with different keys/);
  assert.equal(described.details, raw);
  assert.equal(describeRegistrationError(new Error('boom')).message, 'Registration failed. Something went wrong.');
});

test('a withdrawal to a contract of the deployment says to pick another address', () => {
  const error = Object.assign(new Error('cannot withdraw to a contract of this deployment'), { code: 'WITHDRAWAL_TO_CONTRACT' });
  assert.match(getFriendlyErrorMessage(error, 'Withdraw'), /^You can't withdraw to a pool or token contract/);
});

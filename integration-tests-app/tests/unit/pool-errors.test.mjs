import assert from 'node:assert/strict';
import test from 'node:test';

import { poolErrorMessage } from '../../../app/js/pool-errors.js';
import { formatAmount } from '../../../app/js/ui/notes-view.js';

const terms = { fee: 1000n, format: (amount) => formatAmount(amount, 'XLM', 7) };

// Shaped as the web SDK's coded errors: amounts are base-unit strings.
function refusal(code, amounts = {}) {
  return Object.assign(new Error('the SDK message'), { code, ...amounts });
}

const BELOW = refusal('DEPOSIT_BELOW_MINIMUM', { minimum: '10000' });
const ABOVE = refusal('DEPOSIT_ABOVE_MAXIMUM', { maximum: '1000000000', largestDeposit: '999999000' });

test('each refusal names its amount in the pool token', () => {
  assert.equal(poolErrorMessage(BELOW, terms), 'The smallest deposit is 0.001 XLM.');
  assert.equal(
    poolErrorMessage(ABOVE, terms),
    'You can deposit at most 99.9999 XLM (100 XLM with the pool fee).',
  );
  assert.equal(
    poolErrorMessage(refusal('NO_COMBINATION', { maxSpend: '99000' }), terms),
    'You can send at most 0.0099 XLM. Each transaction pays a 0.0001 XLM pool fee.',
  );
});

test('a deposit that already holds the fee is bounded by the maximum and the minimum after the fee', () => {
  const feeIncluded = { ...terms, feeIncluded: true };
  assert.equal(poolErrorMessage(ABOVE, feeIncluded), 'Public deposit can be at most 100 XLM, pool fee included.');
  assert.equal(
    poolErrorMessage(BELOW, feeIncluded),
    'Public deposit must leave at least 0.001 XLM after the 0.0001 XLM pool fee.',
  );
});

test('a balance that cannot cover the fee says nothing can be sent', () => {
  assert.equal(
    poolErrorMessage(refusal('NO_COMBINATION', { maxSpend: '0' }), terms),
    'You have nothing to send once the 0.0001 XLM pool fee is paid. If you just deposited, try again in a few seconds; otherwise, deposit more first.',
  );
});

test('an empty wallet is asked to deposit without naming the fee', () => {
  assert.equal(
    poolErrorMessage(refusal('NO_SPENDABLE_NOTES'), terms),
    'You have nothing to send yet. If you just deposited, try again in a few seconds; otherwise, deposit first.',
  );
});

test('a pool with no fee never names one', () => {
  const free = { ...terms, fee: 0n };
  const aboveFree = refusal('DEPOSIT_ABOVE_MAXIMUM', { maximum: '1000000000', largestDeposit: '1000000000' });
  assert.equal(poolErrorMessage(aboveFree, free), 'You can deposit at most 100 XLM.');
  assert.equal(poolErrorMessage(refusal('NO_COMBINATION', { maxSpend: '99000' }), free), 'You can send at most 0.0099 XLM.');
  assert.equal(
    poolErrorMessage(refusal('NO_COMBINATION', { maxSpend: '0' }), free),
    'You have nothing to send yet. If you just deposited, try again in a few seconds; otherwise, deposit first.',
  );
  assert.equal(poolErrorMessage(aboveFree, { ...free, feeIncluded: true }), 'Public deposit can be at most 100 XLM.');
  assert.equal(poolErrorMessage(BELOW, { ...free, feeIncluded: true }), 'Public deposit must be at least 0.001 XLM.');
});

test('a paused pool says deposits are paused', () => {
  assert.equal(
    poolErrorMessage(refusal('DEPOSITS_PAUSED'), terms),
    'Deposits into this pool are paused. Withdrawals and transfers still work.',
  );
});

test('an uncoded error falls back to the error message', () => {
  assert.equal(poolErrorMessage(new Error('network down'), terms), null);
});

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

const RULE = 'Selected notes and public deposit must add up to the private outputs, public withdraw and the 0.0001 XLM pool fee.';
const NO_FEE_RULE = 'Selected notes and public deposit must add up to the private outputs and public withdraw.';
const none = { inputs: 0n, deposit: 0n, outputs: 0n, withdraw: 0n };

function unbalanced(gap, amounts, fee = terms.fee) {
  return poolErrorMessage(
    refusal('NOT_BALANCED', { gap }),
    { ...terms, fee, feeIncluded: true, amounts: { ...none, ...amounts } },
  );
}

test('a transfer of the whole input takes the fee off a private output', () => {
  assert.equal(
    unbalanced('-1000', { inputs: 100000n, outputs: 100000n }),
    `${RULE} Remove 0.0001 XLM from a private output.`,
  );
});

test('a deposit of the whole output takes the fee off a private output', () => {
  assert.equal(
    unbalanced('-1000', { deposit: 100000n, outputs: 100000n }),
    `${RULE} Remove 0.0001 XLM from a private output.`,
  );
});

test('a withdrawal of the whole input takes the fee off the withdrawal', () => {
  assert.equal(
    unbalanced('-1000', { inputs: 100000n, withdraw: 100000n }),
    `${RULE} Lower the public withdraw by 0.0001 XLM.`,
  );
});

test('inputs left over go to a private output', () => {
  assert.equal(
    unbalanced('1', { inputs: 100000n, outputs: 98999n }),
    `${RULE} Add 0.0000001 XLM to a private output.`,
  );
});

test('an empty form asks for a note or a deposit', () => {
  assert.equal(unbalanced('-1000', {}), `${RULE} Select a note or enter a public deposit.`);
});

test('a note smaller than the fee asks for more in', () => {
  assert.equal(
    unbalanced('-500', { inputs: 500n }),
    `${RULE} Raise the public deposit by 0.00005 XLM, or select more notes.`,
  );
});

test('a pool with no fee leaves the fee out of the balance rule', () => {
  assert.equal(
    unbalanced('-1', { inputs: 100000n, outputs: 100001n }, 0n),
    `${NO_FEE_RULE} Remove 0.0000001 XLM from a private output.`,
  );
});

test('a pool with no fee still asks for a note when nothing comes in', () => {
  const ask = `${NO_FEE_RULE} Select a note or enter a public deposit.`;
  assert.equal(unbalanced('-50000', { outputs: 50000n }, 0n), ask);
  assert.equal(unbalanced('-10000000', { withdraw: 10000000n }, 0n), ask);
});

test('the gap comes from the SDK, not from the form', () => {
  assert.equal(
    unbalanced('-2000', { inputs: 100000n, outputs: 100000n }),
    `${RULE} Remove 0.0002 XLM from a private output.`,
  );
});

test('a balance refusal without the form has no sentence', () => {
  assert.equal(poolErrorMessage(refusal('NOT_BALANCED', { gap: '-1000' }), terms), null);
});

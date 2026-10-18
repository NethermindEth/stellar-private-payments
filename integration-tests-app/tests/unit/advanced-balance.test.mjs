import assert from 'node:assert/strict';
import test from 'node:test';

import { advancedGap, advancedGapMessage } from '../../../app/js/advanced-balance.js';
import { formatAmount } from '../../../app/js/ui/notes-view.js';

const none = { inputs: 0n, deposit: 0n, outputs: 0n, withdraw: 0n, fee: 1000n };

test('a withdrawal with no outputs pays the fee from the inputs', () => {
  assert.equal(advancedGap({ ...none, inputs: 100000n, withdraw: 99000n }), 0n);
});

const format = (amount) => formatAmount(amount, 'XLM', 7);
const RULE = 'Selected notes and public deposit must add up to the private outputs, public withdraw and the 0.0001 XLM pool fee.';
const NO_FEE_RULE = 'Selected notes and public deposit must add up to the private outputs and public withdraw.';

test('a balanced form has no refusal', () => {
  assert.equal(advancedGapMessage({ ...none, inputs: 100000n, outputs: 99000n }, format), null);
});

test('a transfer of the whole input takes the fee off a private output', () => {
  assert.equal(
    advancedGapMessage({ ...none, inputs: 100000n, outputs: 100000n }, format),
    `${RULE} Remove 0.0001 XLM from a private output.`,
  );
});

test('a deposit of the whole output takes the fee off a private output', () => {
  assert.equal(
    advancedGapMessage({ ...none, deposit: 100000n, outputs: 100000n }, format),
    `${RULE} Remove 0.0001 XLM from a private output.`,
  );
});

test('a withdrawal of the whole input takes the fee off the withdrawal', () => {
  assert.equal(
    advancedGapMessage({ ...none, inputs: 100000n, withdraw: 100000n }, format),
    `${RULE} Lower the public withdraw by 0.0001 XLM.`,
  );
});

test('inputs left over go to a private output', () => {
  assert.equal(
    advancedGapMessage({ ...none, inputs: 100000n, outputs: 98999n }, format),
    `${RULE} Add 0.0000001 XLM to a private output.`,
  );
});

test('an empty form asks for a note or a deposit', () => {
  assert.equal(advancedGapMessage(none, format), `${RULE} Select a note or enter a public deposit.`);
});

test('a note smaller than the fee asks for more in', () => {
  assert.equal(
    advancedGapMessage({ ...none, inputs: 500n }, format),
    `${RULE} Raise the public deposit by 0.00005 XLM, or select more notes.`,
  );
});

test('a pool with no fee leaves the fee out of the rule', () => {
  assert.equal(
    advancedGapMessage({ ...none, fee: 0n, inputs: 100000n, outputs: 100001n }, format),
    `${NO_FEE_RULE} Remove 0.0000001 XLM from a private output.`,
  );
});

test('a pool with no fee still asks for a note when nothing comes in', () => {
  const free = { ...none, fee: 0n };
  const ask = `${NO_FEE_RULE} Select a note or enter a public deposit.`;
  assert.equal(advancedGapMessage({ ...free, outputs: 50000n }, format), ask);
  assert.equal(advancedGapMessage({ ...free, withdraw: 10000000n }, format), ask);
});

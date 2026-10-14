import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyTx, withdrawalsByPk } from '../../../app/js/gvk-classify.js';

test('a spend that pays only the fee is a transfer, and one unit more is a withdrawal', () => {
  assert.equal(classifyTx(true, 100n, 95n, 5n), 'transfer');
  assert.equal(classifyTx(true, 100n, 94n, 5n), 'withdraw');
  assert.equal(classifyTx(false, 0n, 95n, 5n), 'deposit');
});

test('at fee 0 any input above the outputs is a withdrawal', () => {
  assert.equal(classifyTx(true, 100n, 100n, 0n), 'transfer');
  assert.equal(classifyTx(true, 100n, 99n, 0n), 'withdraw');
});

test('a one-sender withdrawal shows what reached the recipient', () => {
  const withdrawn = withdrawalsByPk(new Map([['a', 100n]]), new Map([['a', 40n]]), 5n);
  assert.deepEqual(withdrawn, new Map([['a', 55n]]));
});

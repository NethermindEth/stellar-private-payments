import assert from 'node:assert/strict';
import test from 'node:test';
import { chargeSpend, classifyTx, emptyPkNode, withdrawalsByPk } from '../../../app/js/gvk-classify.js';

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

test('a key that sends 60 of 100 at fee 1 pays the fee once', () => {
  const nodes = new Map();
  const nodeOf = (pk) => nodes.get(pk) ?? nodes.set(pk, emptyPkNode(pk)).get(pk);
  const transfers = chargeSpend(nodeOf, new Map([['a', 100n]]), [['b', 60n], ['a', 39n]], new Map(), 1n);
  assert.deepEqual(transfers, [['a', 'b', 60n]]);
  assert.equal(nodes.get('a').feesPaid, 1n);
  assert.equal(nodes.get('a').feeCount, 1);
});

test('a key that withdraws 99 of 100 at fee 1 pays the fee and withdraws 99', () => {
  const nodes = new Map();
  const nodeOf = (pk) => nodes.get(pk) ?? nodes.set(pk, emptyPkNode(pk)).get(pk);
  chargeSpend(nodeOf, new Map([['a', 100n]]), [], new Map([['a', 99n]]), 1n);
  assert.equal(nodes.get('a').withdrawn, 99n);
  assert.equal(nodes.get('a').feesPaid, 1n);
});

test('a spend from two keys charges each key the fee once', () => {
  const nodes = new Map();
  const nodeOf = (pk) => nodes.get(pk) ?? nodes.set(pk, emptyPkNode(pk)).get(pk);
  chargeSpend(nodeOf, new Map([['a', 60n], ['b', 40n]]), [['c', 90n]], new Map(), 10n);
  assert.deepEqual([nodes.get('a').feeCount, nodes.get('b').feeCount], [1, 1]);
  assert.deepEqual([nodes.get('a').feesPaid, nodes.get('b').feesPaid], [10n, 10n]);
});

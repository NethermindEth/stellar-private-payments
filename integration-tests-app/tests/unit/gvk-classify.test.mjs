import assert from 'node:assert/strict';
import test from 'node:test';
import { chargeSpend, classifyTx, emptyPkNode, keyBalance, withdrawalsByPk } from '../../../app/js/gvk-classify.js';

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

// `a` holds a deposit of 100.
function graph() {
  const nodes = new Map();
  const nodeOf = (pk) => nodes.get(pk) ?? nodes.set(pk, emptyPkNode(pk)).get(pk);
  nodeOf('a').deposited = 100n;
  return { nodes, nodeOf };
}

test('a key that sends 60 of 100 at fee 1 pays the fee and keeps 39', () => {
  const { nodes, nodeOf } = graph();
  const transfers = chargeSpend(nodeOf, new Map([['a', 100n]]), [['b', 60n], ['a', 39n]], new Map(), 1n);
  assert.deepEqual(transfers, [['a', 'b', 60n]]);
  assert.equal(nodes.get('a').feesPaid, 1n);
  assert.equal(keyBalance(nodes.get('a')), 39n);
  assert.equal(keyBalance(nodes.get('b')), 60n);
});

test('a key that withdraws 99 of 100 at fee 1 keeps nothing', () => {
  const { nodes, nodeOf } = graph();
  chargeSpend(nodeOf, new Map([['a', 100n]]), [], new Map([['a', 99n]]), 1n);
  assert.equal(keyBalance(nodes.get('a')), 0n);
});

test('at fee 0 a key keeps what came in less what left', () => {
  const { nodes, nodeOf } = graph();
  chargeSpend(nodeOf, new Map([['a', 100n]]), [['b', 60n], ['a', 40n]], new Map(), 0n);
  assert.equal(keyBalance(nodes.get('a')), 40n);
});

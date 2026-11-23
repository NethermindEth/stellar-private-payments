import assert from 'node:assert/strict';
import test from 'node:test';
import {
  amountByPk,
  collectNotes,
  createNoteIndex,
  normalizedOutputs,
  noteLinks,
  unspentByPk,
} from '../../../app/js/gvk-notes.js';

const c = `0x${'c'.repeat(64)}`;
const note = { note: { pk: 'pk', amount: '5' }, commitment: c };
const output = { commitment: c, note };
const input = { nullifier: 'n', note };
const row = (index, outputs, inputs = []) => ({ tx: { ledger: 100 + index, outputs, inputs }, index, kind: null });
const created = row(0, [output, output]);

test('two outputs that share a commitment are two notes', () => {
  assert.equal(collectNotes([created]).length, 2);
});

test('each spend takes its own copy', () => {
  const rows = [created, row(1, [], [input, input])];
  assert.deepEqual(collectNotes(rows).map((n) => n.spentTxIndex), [1, 1]);
  assert.deepEqual(noteLinks(rows), [['0:output:0', '1:input:0'], ['0:output:1', '1:input:1']]);
});

test('a spend whose output was never loaded is its own record', () => {
  const rows = [row(0, [], [input, input])];
  assert.deepEqual(
    collectNotes(rows).map((n) => [n.noteId, n.createdTxIndex]),
    [['0:input:0', null], ['0:input:1', null]],
  );
  assert.deepEqual(noteLinks(rows), []);
});

test('a spend never takes an output of its own transaction', () => {
  const rows = [row(0, [output], [input])];
  assert.deepEqual(
    collectNotes(rows).map((n) => [n.noteId, n.spentTxIndex]),
    [['0:input:0', 0], ['0:output:0', null]],
  );
  assert.deepEqual(noteLinks(rows), []);
});

test('a filtered view marks the same copy spent as the links', () => {
  const [a, b, s] = [row(0, [output]), row(1, [output]), row(2, [], [input])];
  const notes = collectNotes([a, b, s], [b, s]);
  assert.deepEqual(
    notes.map((n) => [n.noteId, n.createdTxIndex, n.spentTxIndex]),
    [['0:output:0', null, 2], ['1:output:0', 1, null]],
  );
  assert.deepEqual(noteLinks([a, b, s]), [['0:output:0', '2:input:0']]);
});

test('a filtered view shows no ledger from a hidden transaction', () => {
  const [a, s, t] = [row(0, [output]), row(2, [], [input]), row(5, [output])];
  const ledgers = (visible) => collectNotes([a, s, t], visible).flatMap((n) => [n.createdLedger, n.spentLedger]);
  assert.deepEqual(ledgers([s]), [null, 102]);
  assert.deepEqual(ledgers([a]), [100, null]);
});

const pkNote = (pk, amount, id) => ({ note: { pk, amount: `0x${amount.toString(16)}` }, commitment: `0x${id}` });
const balances = (rows) => unspentByPk(collectNotes(rows));

test('a spend with its own deposit leaves the key its change', () => {
  // 100 spent with a 50 deposit at fee 10.
  const held = pkNote('a', 100, 'a1');
  const rows = [
    row(0, [{ commitment: held.commitment, note: held }]),
    row(1, [{ commitment: '0xa2', note: pkNote('a', 140, 'a2') }], [{ nullifier: 'n', note: held }]),
  ];
  assert.deepEqual(balances(rows), new Map([['a', 140n]]));
});

test('a spend from two keys credits the recipient once', () => {
  // 60 and 40 send 90 at fee 10.
  const a = pkNote('a', 60, 'a1');
  const b = pkNote('b', 40, 'b1');
  const rows = [
    row(0, [{ commitment: a.commitment, note: a }, { commitment: b.commitment, note: b }]),
    row(1, [{ commitment: '0xc1', note: pkNote('c', 90, 'c1') }], [{ nullifier: 'na', note: a }, { nullifier: 'nb', note: b }]),
  ];
  assert.deepEqual(balances(rows), new Map([['c', 90n]]));
});

test('incremental balances and lifetime receipts match recomputation after each append', () => {
  const first = pkNote(' A ', 60, 'a1');
  const second = pkNote('b', 40, 'a1');
  const change = pkNote('a', 15, 'a2');
  const recipient = pkNote('c', 80, 'c1');
  const viewOnly = pkNote('view-only', 25, 'd1');
  const inputOnly = pkNote('input-only', 99, 'e1');
  const revealedOnSpend = pkNote('revealed-on-spend', 55, 'f1');
  const outputSlot = (audited) => ({ commitment: audited.commitment, note: audited });
  const inputSlot = (audited, nullifier) => ({ nullifier, note: audited });
  const rows = [
    row(0, [first, second, viewOnly].map(outputSlot)),
    row(1, [change, recipient].map(outputSlot), [inputSlot(second, 'n1')]),
    row(2, [{ commitment: revealedOnSpend.commitment }], [inputSlot(first, 'n2'), { nullifier: 'masked' }]),
    row(3, [], [
      inputSlot(first, 'n3'),
      inputSlot(inputOnly, 'n4'),
      inputSlot(revealedOnSpend, 'n5'),
    ]),
  ];
  const index = createNoteIndex();
  const loaded = [];
  for (const next of rows) {
    index.append(next);
    loaded.push(next);
    const expectedBalances = balances(loaded);
    const expectedReceipts = amountByPk(loaded.flatMap(({ tx }) => normalizedOutputs(tx)).filter((slot) => slot.audited));
    for (const pk of ['a', 'b', 'c', 'view-only', 'input-only', 'revealed-on-spend', 'unknown']) {
      assert.equal(index.balanceOf(` ${pk.toUpperCase()} `), expectedBalances.get(pk) ?? 0n, `balance for ${pk} at row ${next.index}`);
      assert.equal(index.receivedBy(pk), expectedReceipts.get(pk) ?? 0n, `receipts for ${pk} at row ${next.index}`);
    }
  }
});

test('paging hides off-page events while preserving known spends and note links', () => {
  const index = createNoteIndex();
  const deposit = row(1, [output]);
  const spend = row(21, [], [input]);
  index.append(deposit);
  assert.equal(index.visibleNotes([deposit])[0].knownSpent, false);
  index.append(spend);

  const [first] = index.visibleNotes([deposit]);
  assert.equal(first.knownSpent, true);
  assert.equal(first.spentTxIndex, null);
  assert.equal(first.nullifier, null);
  const [second] = index.visibleNotes([spend]);
  assert.equal(second.createdTxIndex, null);
  assert.equal(second.spentTxIndex, 21);
  assert.equal(index.links.get(first.noteId), '21:input:0');
  assert.equal(index.auditedNotes()[0].spentTxIndex, 21);
});

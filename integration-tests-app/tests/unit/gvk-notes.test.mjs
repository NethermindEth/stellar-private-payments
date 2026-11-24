import assert from 'node:assert/strict';
import test from 'node:test';
import { createNoteIndex } from '../../../app/js/gvk-notes.js';

const c = `0x${'c'.repeat(64)}`;
const note = { note: { pk: 'pk', amount: '5' }, commitment: c };
const output = { commitment: c, note };
const input = { nullifier: 'n', note };
const row = (index, outputs, inputs = []) => ({ tx: { ledger: 100 + index, outputs, inputs }, index, kind: null });
const created = row(0, [output, output]);

function indexRows(rows) {
  const index = createNoteIndex();
  rows.forEach(index.append);
  return index;
}

test('two outputs that share a commitment are two notes', () => {
  assert.equal(indexRows([created]).auditedNotes().length, 2);
});

test('each spend takes its own copy', () => {
  const index = indexRows([created, row(1, [], [input, input])]);
  assert.deepEqual(index.auditedNotes().map((n) => n.spentTxIndex), [1, 1]);
  assert.equal(index.links.get('0:output:0'), '1:input:0');
  assert.equal(index.links.get('0:output:1'), '1:input:1');
});

test('a spend whose output was never loaded is its own record', () => {
  const index = indexRows([row(0, [], [input, input])]);
  assert.deepEqual(
    index.auditedNotes().map((n) => [n.noteId, n.createdTxIndex]),
    [['0:input:0', null], ['0:input:1', null]],
  );
  assert.equal(index.links.size, 0);
});

test('a spend never takes an output of its own transaction', () => {
  const index = indexRows([row(0, [output], [input])]);
  assert.deepEqual(
    index.auditedNotes().map((n) => [n.noteId, n.spentTxIndex]),
    [['0:input:0', 0], ['0:output:0', null]],
  );
  assert.equal(index.links.size, 0);
});

test('a filtered view marks the same copy spent as the links', () => {
  const [a, b, s] = [row(0, [output]), row(1, [output]), row(2, [], [input])];
  const index = indexRows([a, b, s]);
  const notes = index.visibleNotes([b, s]);
  assert.deepEqual(
    notes.map((n) => [n.noteId, n.createdTxIndex, n.spentTxIndex]),
    [['0:output:0', null, 2], ['1:output:0', 1, null]],
  );
  assert.equal(index.links.get('2:input:0'), '0:output:0');
  assert.equal(index.links.has('1:output:0'), false);
});

test('a filtered view shows no ledger from a hidden transaction', () => {
  const [a, s, t] = [row(0, [output]), row(2, [], [input]), row(5, [output])];
  const index = indexRows([a, s, t]);
  const ledgers = (visible) => index.visibleNotes(visible).flatMap((n) => [n.createdLedger, n.spentLedger]);
  assert.deepEqual(ledgers([s]), [null, 102]);
  assert.deepEqual(ledgers([a]), [100, null]);
});

const pkNote = (pk, amount, id) => ({ note: { pk, amount: `0x${amount.toString(16)}` }, commitment: `0x${id}` });

test('a spend with its own deposit leaves the key its change', () => {
  // 100 spent with a 50 deposit at fee 10.
  const held = pkNote('a', 100, 'a1');
  const rows = [
    row(0, [{ commitment: held.commitment, note: held }]),
    row(1, [{ commitment: '0xa2', note: pkNote('a', 140, 'a2') }], [{ nullifier: 'n', note: held }]),
  ];
  assert.equal(indexRows(rows).balanceOf('a'), 140n);
});

test('a spend from two keys credits the recipient once', () => {
  // 60 and 40 send 90 at fee 10.
  const a = pkNote('a', 60, 'a1');
  const b = pkNote('b', 40, 'b1');
  const rows = [
    row(0, [{ commitment: a.commitment, note: a }, { commitment: b.commitment, note: b }]),
    row(1, [{ commitment: '0xc1', note: pkNote('c', 90, 'c1') }], [{ nullifier: 'na', note: a }, { nullifier: 'nb', note: b }]),
  ];
  const index = indexRows(rows);
  assert.equal(index.balanceOf('a'), 0n);
  assert.equal(index.balanceOf('b'), 0n);
  assert.equal(index.balanceOf('c'), 90n);
});

test('incremental balances and lifetime receipts after each append', () => {
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
  const initial = { a: 60n, b: 40n, 'view-only': 25n };
  const receipts = { a: 75n, b: 40n, c: 80n, 'view-only': 25n };
  // The first spend supplies b's note, but the earlier a output shares its commitment.
  const afterFirstSpend = { ...receipts, a: 15n };
  const afterSecondSpend = { ...afterFirstSpend, b: 0n };
  const expected = [
    { balance: initial, received: initial, changed: [] },
    { balance: afterFirstSpend, received: receipts, changed: [0] },
    { balance: afterSecondSpend, received: receipts, changed: [0] },
    { balance: afterSecondSpend, received: receipts, changed: [2] },
  ];
  for (const next of rows) {
    const { balance, received, changed } = expected[next.index];
    assert.deepEqual([...index.append(next)], changed);
    for (const pk of ['a', 'b', 'c', 'view-only', 'input-only', 'revealed-on-spend', 'unknown']) {
      assert.equal(index.balanceOf(` ${pk.toUpperCase()} `), balance[pk] ?? 0n, `balance for ${pk} at row ${next.index}`);
      assert.equal(index.receivedBy(pk), received[pk] ?? 0n, `receipts for ${pk} at row ${next.index}`);
    }
  }
  // The spend of the duplicate also touches tx 2, so find the newly visible output by ID.
  assert.equal(index.visibleNotes([rows[2]]).find((note) => note.noteId === '2:output:0')?.audited, revealedOnSpend);
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

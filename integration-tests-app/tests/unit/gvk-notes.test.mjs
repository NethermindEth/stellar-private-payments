import assert from 'node:assert/strict';
import test from 'node:test';
import { collectNotes, noteLinks, unspentByPk } from '../../../app/js/gvk-notes.js';

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


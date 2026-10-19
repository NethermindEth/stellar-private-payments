import assert from 'node:assert/strict';
import test from 'node:test';
import { collectNotes, noteLinks } from '../../../app/js/gvk-notes.js';

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

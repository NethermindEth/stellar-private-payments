import assert from 'node:assert/strict';
import test from 'node:test';
import { disclosedCopy, preselectNotes, sameNote } from '../../../app/js/disclosure-notes.js';

const c = 'c'.repeat(64);
const d = 'd'.repeat(64);
const note = (commitment, leafIndex, spent, poolContractId = 'pool') => ({
  id: `0x${commitment}`,
  poolContractId,
  amount: '5',
  spent,
  leafIndex,
  createdAtLedger: 100 - leafIndex,
});
const [spentC1, c7, c3, d0] = [note(c, 1, true), note(c, 7, false), note(c, 3, false), note(d, 0, false)];
const otherC5 = note(c, 5, false, 'other');
const notes = [spentC1, c7, c3, d0, otherC5];

test('a link to a repeated commitment selects its lowest unspent copy', () => {
  assert.deepEqual(preselectNotes(notes, [`0x${c}`]), [c3]);
});

test('each commitment is selected once', () => {
  assert.deepEqual(preselectNotes(notes, [c, d, c]), [c3, d0]);
});

test('copies are told apart by leaf', () => {
  assert.equal(sameNote(c3, c7), false);
  assert.equal(disclosedCopy(notes, c7), c3);
});

test('copies in two pools are told apart by pool', () => {
  assert.equal(sameNote(c3, { ...c3, poolContractId: 'other' }), false);
  assert.equal(disclosedCopy(notes, otherC5), otherC5);
  assert.deepEqual(preselectNotes(notes, [c], 'other'), [otherC5]);
});

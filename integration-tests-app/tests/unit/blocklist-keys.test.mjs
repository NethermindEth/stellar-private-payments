import assert from 'node:assert/strict';
import test from 'node:test';

import { blocklistInsertCall, blocklistKeyToNoteKey, parseBlocklistKeys, unreadBlocklistWarning } from '../../../app/js/blocklist-keys.js';

const ONE = `0x01${'00'.repeat(31)}`;
const TWO = `0x02${'00'.repeat(31)}`;
const BIG = `0x${'00'.repeat(31)}ff`;

test('parseBlocklistKeys returns the keys in the order of their lines', () => {
  assert.deepEqual(parseBlocklistKeys(`${ONE}\n${TWO}\n${BIG}`), [1n, 2n, 0xffn << 248n]);
});

test('parseBlocklistKeys skips a blank line', () => {
  assert.deepEqual(parseBlocklistKeys(`${ONE}\n  \n${TWO}\n`), [1n, 2n]);
});

test('parseBlocklistKeys keeps a repeated key once', () => {
  assert.deepEqual(parseBlocklistKeys(`${ONE}\n${TWO}\n${ONE}`), [1n, 2n]);
});

test('parseBlocklistKeys refuses a malformed line and names it', () => {
  assert.throws(
    () => parseBlocklistKeys(`${ONE}\n\n0x1234\n${TWO}`),
    { message: 'Line 3 is not a note public key (0x and 64 hex digits)' },
  );
});

test('blocklistKeyToNoteKey gives the note public key parseBlocklistKeys reads back as the key', () => {
  const key = BigInt(`0x${Array.from({ length: 32 }, (_, i) => (i + 1).toString(16).padStart(2, '0')).join('')}`);
  assert.deepEqual(parseBlocklistKeys(blocklistKeyToNoteKey(key)), [key]);
});

test('blocklistInsertCall lists each key with itself in one insert_leaves call', () => {
  assert.deepEqual(blocklistInsertCall([1n, 2n], true), { method: 'insert_leaves', args: { entries: [[1n, 1n], [2n, 2n]] } });
});

test('blocklistInsertCall falls back to insert_leaf for one key on a blocklist without insert_leaves', () => {
  assert.deepEqual(blocklistInsertCall([1n], false), { method: 'insert_leaf', args: { key: 1n, value: 1n } });
});

test('blocklistInsertCall refuses several keys on a blocklist without insert_leaves', () => {
  assert.throws(
    () => blocklistInsertCall([1n, 2n], false),
    { message: 'This blocklist predates batched inserts. Add one key at a time.' },
  );
});

test('unreadBlocklistWarning warns of a blocklist no pool reads, and of no other', () => {
  assert.equal(
    unreadBlocklistWarning('MANIFEST_BLOCKLIST', ['NEW_BLOCKLIST']),
    'No pool on the Pools tab reads MANIFEST_BLOCKLIST, so a key written there blocks or releases no one. Build the call anyway?',
  );
  assert.equal(unreadBlocklistWarning('NEW_BLOCKLIST', ['NEW_BLOCKLIST', 'NEW_BLOCKLIST']), null);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  applyOwnerLookup,
  createOwnerBook,
  createOwnersRetry,
  nextOwnersRetry,
  ownerAddresses,
  ownerCsvFields,
  ownerStatus,
  ownersRetryState,
  pendingPks,
} from '../../../app/js/gvk-owners.js';

const pkA = `0x${'a'.repeat(64)}`;
const pkB = `0x${'b'.repeat(64)}`;

test('a key is pending, with no owners, until a lookup settles it', () => {
  const book = createOwnerBook();
  assert.equal(ownerStatus(book, pkA), 'pending');
  assert.deepEqual(ownerAddresses(book, pkA), []);
  assert.deepEqual(ownerCsvFields(book, pkA), ['', 'pending']);
  assert.deepEqual(pendingPks(book, [pkA]), [pkA]);
});

test('a lookup settles every queried key, owners or not', () => {
  const book = createOwnerBook();
  const owners = [
    { noteKey: pkA.toUpperCase().replace('0X', '0x'), address: 'GZED' },
    { noteKey: pkA, address: 'GAMY' },
  ];
  applyOwnerLookup(book, [pkA, pkB], owners);
  assert.deepEqual(ownerAddresses(book, pkA), ['GZED', 'GAMY']);
  assert.deepEqual(ownerCsvFields(book, pkA), ['GZED;GAMY', 'registered']);
  assert.deepEqual(ownerCsvFields(book, pkB), ['', 'unregistered']);
  assert.deepEqual(pendingPks(book, [pkA, pkB]), []);
});

test('pending keys are normalized and deduplicated, a missing PK has no status', () => {
  const book = createOwnerBook();
  assert.deepEqual(pendingPks(book, [` ${pkA.toUpperCase()} `, pkA, null, '']), [pkA.toLowerCase()]);
  assert.equal(ownerStatus(book, null), null);
  assert.deepEqual(ownerCsvFields(book, ''), ['', '']);
});

test('waiting backs off to 60 s and never stops', () => {
  const retry = createOwnersRetry();
  const delays = Array.from({ length: 7 }, () => nextOwnersRetry(retry, 'waiting'));
  assert.deepEqual(delays, [5_000, 10_000, 20_000, 40_000, 60_000, 60_000, 60_000]);
  assert.equal(ownersRetryState(retry), 'waiting');
  assert.equal(nextOwnersRetry(retry, 'settled'), null);
  assert.equal(ownersRetryState(retry), 'ok');
  assert.equal(nextOwnersRetry(retry, 'waiting'), 5_000);
});

test('errors stop after three in a row; a valid answer resets the streak', () => {
  const retry = createOwnersRetry();
  assert.equal(nextOwnersRetry(retry, 'error'), 5_000);
  assert.equal(nextOwnersRetry(retry, 'error'), 10_000);
  nextOwnersRetry(retry, 'waiting');
  assert.equal(nextOwnersRetry(retry, 'error'), 5_000);
  assert.equal(nextOwnersRetry(retry, 'error'), 10_000);
  assert.equal(nextOwnersRetry(retry, 'error'), null);
  assert.equal(ownersRetryState(retry), 'stopped');
  nextOwnersRetry(retry, 'settled');
  assert.equal(ownersRetryState(retry), 'ok');
});

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  IndexerProgressTimeoutError,
  syncedLedgerFromConsole,
  waitForIndexerProgress,
} from '../../src/indexer.mjs';

function fakePage() {
  const listeners = new Map();
  let closed = false;
  return {
    on(event, listener) {
      const bucket = listeners.get(event) || new Set();
      bucket.add(listener);
      listeners.set(event, bucket);
    },
    off(event, listener) {
      listeners.get(event)?.delete(listener);
    },
    emit(event, payload) {
      for (const listener of [...(listeners.get(event) || [])]) listener(payload);
    },
    listenerCount(event) { return listeners.get(event)?.size || 0; },
    isClosed() { return closed; },
    close() { closed = true; this.emit('close'); },
  };
}

function fakeTimers() {
  const callbacks = new Set();
  return {
    setTimer(callback) { callbacks.add(callback); return callback; },
    clearTimer(callback) { callbacks.delete(callback); },
    fireAll() { for (const callback of [...callbacks]) callback(); },
  };
}

test('parses only indexer synced-ledger console messages', () => {
  assert.equal(syncedLedgerFromConsole('[INDEXER] synced to ledger 42'), 42);
  assert.equal(syncedLedgerFromConsole({ text: () => 'unrelated' }), null);
});

test('waitForIndexerProgress ignores repeated ledgers and cleans up after progress', async () => {
  const page = fakePage();
  const timers = fakeTimers();
  const pending = waitForIndexerProgress(page, { after: 10, setTimer: timers.setTimer, clearTimer: timers.clearTimer });

  page.emit('console', { text: () => '[INDEXER] synced to ledger 10' });
  page.emit('console', { text: () => '[INDEXER] synced to ledger 10' });
  page.emit('console', { text: () => '[INDEXER] synced to ledger 11' });

  assert.deepEqual(await pending, { ledger: 11, after: 10, observedLedgers: [10, 11] });
  assert.equal(page.listenerCount('console'), 0);
  assert.equal(page.listenerCount('close'), 0);
});

test('waitForIndexerProgress reports observed ledgers and removes late listeners on timeout', async () => {
  const page = fakePage();
  const timers = fakeTimers();
  const pending = waitForIndexerProgress(page, { after: 5, timeoutMs: 25, setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  page.emit('console', { text: () => '[INDEXER] synced to ledger 5' });
  timers.fireAll();

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof IndexerProgressTimeoutError);
    assert.deepEqual(error.observedLedgers, [5]);
    return true;
  });
  assert.equal(page.listenerCount('console'), 0);
  page.emit('console', { text: () => '[INDEXER] synced to ledger 6' });
});

test('waitForIndexerProgress rejects and cleans up if the page closes', async () => {
  const page = fakePage();
  const timers = fakeTimers();
  const pending = waitForIndexerProgress(page, { after: 1, setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  page.close();
  await assert.rejects(pending, /page closed/);
  assert.equal(page.listenerCount('console'), 0);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { waitForNotes, waitForNotesAfterIndexer } from '../../src/notes.mjs';

function fakeNotesPage(snapshots) {
  let index = 0;
  const page = {
    getByTestId(testId) {
      if (testId === 'advanced-notes-table') {
        return {
          async getAttribute(name) {
            const snapshot = snapshots[Math.min(index, snapshots.length - 1)];
            return snapshot.table[name] ?? null;
          },
        };
      }
      if (testId === 'advanced-note') {
        return {
          async evaluateAll(project) {
            const snapshot = snapshots[Math.min(index++, snapshots.length - 1)];
            return project(snapshot.rows.map((row) => ({
              getAttribute(name) { return row[name] ?? null; },
            })));
          },
        };
      }
      throw new Error(`unexpected test id: ${testId}`);
    },
  };
  return page;
}

function readySnapshot(rows) {
  return {
    table: {
      'data-refresh-sequence': '2',
      'data-state': 'ready',
      'data-note-count': String(rows.length),
    },
    rows,
  };
}

test('waitForNotes resolves only after the table count and predicate are ready', async () => {
  let now = 0;
  const page = fakeNotesPage([
    readySnapshot([]),
    readySnapshot([{ 'data-note-id': 'note-a', 'data-note-state': 'available', 'data-note-ledger': '40' }]),
  ]);

  const result = await waitForNotes(page, {
    minCount: 1,
    predicate: (note) => note.state === 'available',
    waitOptions: {
      now: () => now,
      sleep: async (ms) => { now += ms; },
    },
  });

  assert.equal(result.value.matchingNotes[0].id, 'note-a');
  assert.equal(result.elapsedMs, 200);
});

test('waitForNotes accepts a ready empty table when minCount is zero', async () => {
  const result = await waitForNotes(fakeNotesPage([readySnapshot([])]), {
    minCount: 0,
    waitOptions: {
      now: () => 0,
      sleep: async () => { throw new Error('empty ready table should not sleep'); },
    },
  });

  assert.deepEqual(result.value.matchingNotes, []);
});

test('waitForNotesAfterIndexer waits for progress before reading the table', async () => {
  const listeners = new Map();
  const page = Object.assign(fakeNotesPage([
    readySnapshot([{ 'data-note-id': 'note-b', 'data-note-state': 'available', 'data-note-ledger': '41' }]),
  ]), {
    on(event, listener) { listeners.set(event, listener); },
    off(event) { listeners.delete(event); },
    isClosed() { return false; },
  });
  const pending = waitForNotesAfterIndexer(page, {
    afterLedger: 40,
    indexer: { setTimer: () => null, clearTimer: () => {} },
  });
  listeners.get('console')({ text: () => '[INDEXER] synced to ledger 41' });

  const result = await pending;
  assert.equal(result.progress.ledger, 41);
  assert.equal(result.notes.matchingNotes[0].id, 'note-b');
});

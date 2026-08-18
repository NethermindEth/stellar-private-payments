import { waitForCondition } from './waits.mjs';
import { waitForIndexerProgress } from './indexer.mjs';

function asNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

export async function readNotes(page) {
  const table = page.getByTestId('advanced-notes-table');
  const rows = page.getByTestId('advanced-note');
  const [refreshSequence, refreshState, noteCount, notes] = await Promise.all([
    table.getAttribute('data-refresh-sequence'),
    table.getAttribute('data-state'),
    table.getAttribute('data-note-count'),
    rows.evaluateAll((elements) => elements.map((row) => ({
      id: row.getAttribute('data-note-id'),
      state: row.getAttribute('data-note-state'),
      createdAtLedger: Number(row.getAttribute('data-note-ledger')),
    }))),
  ]);

  return {
    refreshSequence: asNumber(refreshSequence),
    refreshState: refreshState || 'unknown',
    noteCount: asNumber(noteCount),
    notes,
  };
}

/** Wait for a notes-table snapshot satisfying a count and/or predicate. */
export async function waitForNotes(page, {
  minCount = 0,
  predicate = () => true,
  timeoutMs = 30_000,
  intervalMs = 200,
  waitOptions = {},
} = {}) {
  if (!Number.isInteger(minCount) || minCount < 0) throw new TypeError('minCount must be a non-negative integer');
  if (typeof predicate !== 'function') throw new TypeError('predicate must be a function');

  return waitForCondition({
    operation: 'notes:ready',
    timeoutMs,
    intervalMs,
    ...waitOptions,
    observe: async () => {
      const snapshot = await readNotes(page);
      return {
        ...snapshot,
        matchingNotes: snapshot.notes.filter(predicate),
      };
    },
    isReady: (snapshot) => (
      snapshot.refreshState === 'ready' &&
      snapshot.noteCount >= minCount &&
      (minCount === 0 || snapshot.matchingNotes.length > 0)
    ),
  });
}

/**
 * Compose a ledger-progress boundary with notes readiness. A ledger event only
 * establishes that the indexer moved; the subsequent table predicate proves
 * the user-visible note state is ready.
 */
export async function waitForNotesAfterIndexer(page, {
  afterLedger,
  indexer = {},
  notes = {},
} = {}) {
  if (!Number.isFinite(afterLedger)) throw new TypeError('afterLedger is required');
  const progress = await waitForIndexerProgress(page, { after: afterLedger, ...indexer });
  const ready = await waitForNotes(page, notes);
  return { progress, notes: ready.value, elapsedMs: ready.elapsedMs };
}

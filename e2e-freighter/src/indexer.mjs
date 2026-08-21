// Indexer progress primitives backed by the SDK's browser console signal.
// The signal is diagnostic-only application output; it contains a ledger
// number, never account or note data.

const SYNCED_LEDGER_RE = /\[INDEXER\] synced to ledger (\d+)/;

export class IndexerProgressTimeoutError extends Error {
  constructor({ after, timeoutMs, observedLedgers }) {
    super(
      `[indexer] no synced ledger greater than ${after} within ${timeoutMs}ms; ` +
      `observed ledgers: ${JSON.stringify(observedLedgers)}`,
    );
    this.name = 'IndexerProgressTimeoutError';
    this.after = after;
    this.timeoutMs = timeoutMs;
    this.observedLedgers = observedLedgers;
  }
}

export function syncedLedgerFromConsole(message) {
  const text = typeof message === 'string' ? message : message?.text?.();
  if (typeof text !== 'string') return null;
  const match = text.match(SYNCED_LEDGER_RE);
  return match ? Number(match[1]) : null;
}

/**
 * Wait for an indexer console signal strictly greater than `after`.
 *
 * One listener remains active for the whole wait, so repeated equal-ledger
 * events are ignored without an unsubscribe/re-subscribe gap. The optional
 * timer hooks make cleanup and timeout behavior deterministic in unit tests.
 */
export function waitForIndexerProgress(page, {
  after = -1,
  timeoutMs = 15_000,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (!page?.on || !page?.off) throw new TypeError('waitForIndexerProgress requires a Playwright page');
  if (!Number.isFinite(after)) throw new TypeError('after must be a finite ledger number');
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new TypeError('timeoutMs must be a non-negative number');

  return new Promise((resolve, reject) => {
    const observedLedgers = [];
    let settled = false;
    let timer;

    const cleanup = () => {
      if (timer !== undefined) clearTimer(timer);
      page.off('console', onConsole);
      page.off('close', onClose);
    };
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn(value);
    };
    const onConsole = (message) => {
      const ledger = syncedLedgerFromConsole(message);
      if (ledger === null || observedLedgers.includes(ledger)) return;
      observedLedgers.push(ledger);
      if (ledger > after) {
        settle(resolve, { ledger, after, observedLedgers: [...observedLedgers] });
      }
    };
    const onClose = () => {
      settle(reject, new Error(`[indexer] page closed while waiting for a synced ledger greater than ${after}`));
    };

    page.on('console', onConsole);
    page.on('close', onClose);
    if (page.isClosed?.()) {
      onClose();
      return;
    }
    timer = setTimer(() => {
      settle(reject, new IndexerProgressTimeoutError({ after, timeoutMs, observedLedgers }));
    }, timeoutMs);
  });
}

export function waitForSyncedLedger(page, options) {
  return waitForIndexerProgress(page, { ...options, after: -1 });
}

// Bounded polling primitives shared by Freighter E2E operations.
//
// Playwright's own assertions are ideal when a single locator is enough. This
// helper covers operation-level readiness that needs several observable values
// and produces the same actionable timeout shape everywhere.

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function observedError(error) {
  return {
    error: error instanceof Error ? error.message : String(error),
  };
}

function formatObservedState(value) {
  if (value === undefined) return 'undefined';
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export class WaitTimeoutError extends Error {
  constructor({ operation, elapsedMs, lastObservedState }) {
    super(
      `[wait:${operation}] timed out after ${elapsedMs}ms; ` +
      `last observed state: ${formatObservedState(lastObservedState)}`,
    );
    this.name = 'WaitTimeoutError';
    this.operation = operation;
    this.elapsedMs = elapsedMs;
    this.lastObservedState = lastObservedState;
  }
}

/**
 * Poll an observable state until its readiness predicate succeeds.
 *
 * `now` and `sleep` are injectable so the timeout behavior has deterministic
 * unit coverage without waiting in real time. `ignoreError` decides which
 * observation failures are transient (the default treats all of them as
 * transient, which is what a locator that is not attached yet needs).
 */
export async function waitForCondition({
  operation,
  observe,
  isReady = Boolean,
  timeoutMs = 10_000,
  intervalMs = 100,
  now = Date.now,
  sleep = defaultSleep,
  ignoreError = () => true,
} = {}) {
  if (!operation) throw new TypeError('waitForCondition requires an operation');
  if (typeof observe !== 'function') throw new TypeError('waitForCondition requires observe');
  if (typeof isReady !== 'function') throw new TypeError('waitForCondition requires isReady');
  if (typeof ignoreError !== 'function') throw new TypeError('ignoreError must be a function');
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new TypeError('timeoutMs must be a non-negative number');
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) throw new TypeError('intervalMs must be a positive number');

  const startedAt = now();
  let lastObservedState;

  while (true) {
    try {
      const value = await observe();
      lastObservedState = value;
      if (isReady(value)) {
        return {
          value,
          elapsedMs: now() - startedAt,
          lastObservedState,
        };
      }
    } catch (error) {
      // "Not attached yet" is the normal case and must keep polling. An
      // observation that can never succeed (a closed page, or a state the
      // caller knows is terminal) should surface now rather than after the
      // whole deadline, so callers can opt out of swallowing it.
      if (!ignoreError(error)) throw error;
      lastObservedState = observedError(error);
    }

    const elapsedMs = now() - startedAt;
    if (elapsedMs >= timeoutMs) {
      throw new WaitTimeoutError({ operation, elapsedMs, lastObservedState });
    }

    await sleep(Math.min(intervalMs, timeoutMs - elapsedMs));
  }
}

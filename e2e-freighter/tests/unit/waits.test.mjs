import assert from 'node:assert/strict';
import test from 'node:test';

import { WaitTimeoutError, waitForCondition } from '../../src/waits.mjs';

test('waitForCondition returns the first ready observed state', async () => {
  let now = 0;
  const states = ['starting', 'syncing', 'ready'];

  const result = await waitForCondition({
    operation: 'unit-ready-state',
    observe: async () => states.shift(),
    isReady: (state) => state === 'ready',
    timeoutMs: 100,
    intervalMs: 10,
    now: () => now,
    sleep: async (ms) => { now += ms; },
  });

  assert.deepEqual(result, {
    value: 'ready',
    elapsedMs: 20,
    lastObservedState: 'ready',
  });
});

test('waitForCondition preserves the operation and last observed state on timeout', async () => {
  let now = 0;

  await assert.rejects(
    waitForCondition({
      operation: 'unit-timeout',
      observe: async () => ({ phase: 'proving' }),
      isReady: () => false,
      timeoutMs: 20,
      intervalMs: 10,
      now: () => now,
      sleep: async (ms) => { now += ms; },
    }),
    (error) => {
      assert.ok(error instanceof WaitTimeoutError);
      assert.equal(error.operation, 'unit-timeout');
      assert.equal(error.elapsedMs, 20);
      assert.deepEqual(error.lastObservedState, { phase: 'proving' });
      assert.match(error.message, /last observed state: {"phase":"proving"}/);
      return true;
    },
  );
});

test('waitForCondition records an observer error as its final state', async () => {
  let now = 0;

  await assert.rejects(
    waitForCondition({
      operation: 'unit-observer-error',
      observe: async () => { throw new Error('page closed'); },
      timeoutMs: 0,
      now: () => now,
      sleep: async () => {},
    }),
    (error) => {
      assert.deepEqual(error.lastObservedState, { error: 'page closed' });
      return true;
    },
  );
});

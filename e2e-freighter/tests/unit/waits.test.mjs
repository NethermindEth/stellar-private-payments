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

test('waitForCondition rethrows an observer error the caller marks as fatal', async () => {
  let now = 0;
  let polls = 0;

  await assert.rejects(
    waitForCondition({
      operation: 'unit-fatal-observer-error',
      observe: async () => { polls += 1; throw new Error('page is closed'); },
      timeoutMs: 10_000,
      intervalMs: 10,
      now: () => now,
      sleep: async (ms) => { now += ms; },
      ignoreError: (error) => !/closed/i.test(error.message),
    }),
    (error) => {
      assert.equal(error.message, 'page is closed');
      assert.equal(polls, 1, 'a fatal observation must not keep polling');
      return true;
    },
  );
});

test('waitForCondition keeps swallowing observer errors by default', async () => {
  let now = 0;
  await assert.rejects(
    waitForCondition({
      operation: 'unit-default-swallows',
      observe: async () => { throw new Error('locator not attached'); },
      timeoutMs: 20,
      intervalMs: 10,
      now: () => now,
      sleep: async (ms) => { now += ms; },
    }),
    (error) => {
      assert.ok(error instanceof WaitTimeoutError);
      assert.deepEqual(error.lastObservedState, { error: 'locator not attached' });
      return true;
    },
  );
});

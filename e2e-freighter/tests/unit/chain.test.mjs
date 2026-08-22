import assert from 'node:assert/strict';
import test from 'node:test';

import { waitForTransactionSuccess } from '../../src/chain.mjs';

test('waitForTransactionSuccess retries until the transaction succeeds', async () => {
  let now = 0;
  let calls = 0;
  const status = await waitForTransactionSuccess('abc', {
    rpcUrl: 'http://rpc.test',
    fetchFn: async (_url, options) => {
      calls += 1;
      assert.ok(options.signal, 'each request has an abort signal');
      return { json: async () => ({ result: { status: calls === 1 ? 'NOT_FOUND' : 'SUCCESS' } }) };
    },
    now: () => now,
    sleepFn: async (ms) => { now += ms; },
  });

  assert.equal(status, 'SUCCESS');
  assert.equal(calls, 2);
});

test('waitForTransactionSuccess fails at its deadline after retryable errors', async () => {
  let now = 0;
  await assert.rejects(
    waitForTransactionSuccess('abc', {
      rpcUrl: 'http://rpc.test',
      timeoutMs: 1_000,
      fetchFn: async () => { throw new Error('unavailable'); },
      now: () => now,
      sleepFn: async (ms) => { now += ms; },
    }),
    /did not resolve within 1000ms/,
  );
});

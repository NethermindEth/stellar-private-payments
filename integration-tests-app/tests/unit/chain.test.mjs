import assert from 'node:assert/strict';
import test from 'node:test';

import { envelopeSourceAccount, waitForTransactionSuccess } from '../../src/chain.mjs';

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

// GAAA…AWHF is the address of the all-zero ed25519 key.
const ZERO_KEY_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

test('envelopeSourceAccount reads a plain and a muxed source account', () => {
  const plain = Buffer.alloc(40);
  plain.writeInt32BE(2, 0);
  assert.equal(envelopeSourceAccount(plain.toString('base64')), ZERO_KEY_ADDRESS);

  const muxed = Buffer.alloc(48);
  muxed.writeInt32BE(2, 0);
  muxed.writeInt32BE(0x100, 4);
  muxed.fill(0xff, 8, 16);
  assert.equal(envelopeSourceAccount(muxed.toString('base64')), ZERO_KEY_ADDRESS);
});

test('envelopeSourceAccount refuses a fee-bump envelope', () => {
  const feeBump = Buffer.alloc(48);
  feeBump.writeInt32BE(5, 0);
  assert.throws(() => envelopeSourceAccount(feeBump.toString('base64')), /unsupported envelope type 5/);
});

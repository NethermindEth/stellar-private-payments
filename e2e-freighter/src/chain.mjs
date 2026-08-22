// Chain-level confirmation helper. Transaction success is confirmed through
// Soroban RPC rather than an eventually consistent UI.

import { createLogger } from './logger.mjs';

const log = createLogger('chain');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Poll Soroban RPC's getTransaction until the transaction resolves.
// https://developers.stellar.org/docs/data/rpc/api-reference/methods/getTransaction
export async function waitForTransactionSuccess(hash, {
  rpcUrl,
  timeoutMs = 60_000,
  requestTimeoutMs = 10_000,
  fetchFn = fetch,
  now = Date.now,
  sleepFn = sleep,
} = {}) {
  const deadline = now() + timeoutMs;
  let lastStatus = 'NOT_FOUND';
  while (now() < deadline) {
    const remainingMs = deadline - now();
    const controller = new AbortController();
    const requestTimer = setTimeout(() => controller.abort(), Math.min(requestTimeoutMs, remainingMs));
    try {
      const res = await fetchFn(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTransaction', params: { hash } }),
        signal: controller.signal,
      });
      const body = await res.json();
      lastStatus = body?.result?.status || 'NOT_FOUND';
      log.debug('polling', hash.slice(0, 8) + '...', 'status:', lastStatus);
      if (lastStatus === 'SUCCESS' || lastStatus === 'FAILED') return lastStatus;
    } catch (error) {
      lastStatus = `RPC transport error: ${error instanceof Error ? error.message : String(error)}`;
      log.warn('transaction confirmation request failed; retrying:', lastStatus);
    } finally {
      clearTimeout(requestTimer);
    }
    await sleepFn(Math.min(2_000, Math.max(0, deadline - now())));
  }
  throw new Error(`waitForTransactionSuccess: transaction ${hash} did not resolve within ${timeoutMs}ms (last status: ${lastStatus})`);
}

// Return a structured confirmation result for composable E2E operations.
// UI submission and RPC confirmation remain separate evidence boundaries.
export async function confirmTransaction(hash, options) {
  const status = await waitForTransactionSuccess(hash, options);
  return { transactionHash: hash, status };
}

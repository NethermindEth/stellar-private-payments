// Chain-level confirmation helper, shared across tests. Extracted from
// tests/02-deposit.mjs's original inline version — proof-of-success for a
// submitted transaction must come from the chain itself, never from a UI
// balance display (see 02-deposit.mjs's module comment for why: the
// displayed balance is eventually consistent against a lagging backend
// indexer with no client-observable freshness signal).

import { createLogger } from './logger.mjs';

const log = createLogger('chain');

// Poll Soroban RPC's getTransaction until the transaction resolves.
// https://developers.stellar.org/docs/data/rpc/api-reference/methods/getTransaction
export async function waitForTransactionSuccess(hash, { rpcUrl, timeoutMs = 60000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastStatus = 'NOT_FOUND';
  while (Date.now() < deadline) {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTransaction', params: { hash } }),
    });
    const body = await res.json();
    lastStatus = body?.result?.status || 'NOT_FOUND';
    log.debug('polling', hash.slice(0, 8) + '...', 'status:', lastStatus);
    if (lastStatus === 'SUCCESS' || lastStatus === 'FAILED') return lastStatus;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`waitForTransactionSuccess: transaction ${hash} did not resolve within ${timeoutMs}ms (last status: ${lastStatus})`);
}
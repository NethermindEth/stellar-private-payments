import assert from 'node:assert/strict';
import test from 'node:test';

import { waitForSubmittedTransaction, waitForToast } from '../../src/moveFunds.mjs';

function fakePage(toasts) {
  return {
    getByTestId(testId) {
      assert.equal(testId, 'toast');
      return {
        async evaluateAll(project) {
          return project(toasts.map((toast) => ({
            getAttribute(name) { return toast[name] ?? null; },
            querySelector(selector) {
              assert.equal(selector, '[data-testid="toast-message"]');
              return { textContent: toast.message || '' };
            },
          })));
        },
      };
    },
  };
}

test('waitForSubmittedTransaction ignores stale toasts and returns the latest matching hash', async () => {
  const page = fakePage([
    { 'data-toast-origin': 'deposit', 'data-transaction-hash': 'old', 'data-state': 'visible' },
    { 'data-toast-origin': 'deposit', 'data-transaction-hash': 'new', 'data-state': 'visible' },
  ]);
  const toast = await waitForSubmittedTransaction(page, {
    origin: 'deposit',
    previousHashes: ['old'],
  });
  assert.equal(toast.transactionHash, 'new');
});

test('waitForToast returns a visible matching error toast without requiring a transaction hash', async () => {
  const toast = await waitForToast(fakePage([
    { 'data-toast-origin': 'deposit', 'data-state': 'visible', message: 'Transaction simulation failed. The contract rejected the transaction.' },
  ]), {
    origin: 'deposit',
    predicate: (candidate) => /simulation failed/i.test(candidate.message),
  });
  assert.match(toast.message, /simulation failed/i);
});

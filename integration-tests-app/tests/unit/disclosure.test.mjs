import assert from 'node:assert/strict';
import test from 'node:test';

import { loadDisclosureReceipt, parseDisclosureReceipt, verifyDisclosure } from '../../src/disclosure.mjs';

function fakePage() {
  const states = {
    'disclosure-receipt-summary': 'idle',
    'disclosure-verification-results': 'idle',
  };
  const filled = [];
  return {
    filled,
    getByTestId(testId) {
      const locator = {
        async fill(value) { filled.push([testId, value]); },
        async click() {
          if (testId === 'disclosure-load-receipt') states['disclosure-receipt-summary'] = 'ready';
          if (testId === 'disclosure-verify-submit') states['disclosure-verification-results'] = 'complete';
        },
        async getAttribute(name) { return name === 'data-state' ? states[testId] : null; },
        async innerText() { return testId === 'disclosure-receipt-json' ? '{"version":1}' : ''; },
        async evaluateAll(project) {
          return project([{ getAttribute: () => 'unspent' }]);
        },
        locator(selector) {
          assert.equal(selector, '[data-testid^="disclosure-check-"]');
          return {
            async evaluateAll(project) {
              return project([
                {
                  getAttribute(name) {
                    if (name === 'data-testid') return 'disclosure-check-proof';
                    if (name === 'data-state') return 'pass';
                    return null;
                  },
                },
              ]);
            },
          };
        },
      };
      return locator;
    },
  };
}

test('receipt parsing reports malformed input', () => {
  assert.throws(() => parseDisclosureReceipt('{'), /could not be parsed/);
});

test('load and verify operations compose through stable UI states', async () => {
  const page = fakePage();
  const receipt = await loadDisclosureReceipt(page, { version: 1 });
  assert.equal(receipt.version, 1);
  assert.equal(page.filled[0][0], 'disclosure-receipt-input');
  assert.deepEqual(await verifyDisclosure(page), {
    state: 'complete',
    noteStates: ['unspent'],
    checks: { proof: 'pass' },
  });
});

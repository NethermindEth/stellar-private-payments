// Wallet connect smoke test.
//
// By the time run() is called, the runner has already unlocked Freighter
// and called connectApp() — which itself exercises Freighter's grant-access
// approval path (auto-approved here, since APPROVE=auto; tolerates a
// previously-granted origin needing no popup at all). This test's job is
// just to assert the connected end state is what it actually looks like in
// the app, proving the whole launch -> unlock -> connect pipeline works.

import { createLogger } from '../src/logger.mjs';

const log = createLogger('01-connect');

function assert(condition, message) {
  if (!condition) {
    log.error('FAIL:', message);
    throw new Error(`01-connect: ${message}`);
  }
}

export async function run({ page }) {
  const connectBtnVisible = await page
    .getByText('Connect Freighter', { exact: true })
    .isVisible()
    .catch(() => false);
  assert(!connectBtnVisible, '"Connect Freighter" is still visible after connecting');

  const addressVisible = await page.getByText(/^G[A-Z2-7]{4,10}\.{3}[A-Z2-7]{4,10}$/).isVisible().catch(() => false);
  assert(addressVisible, 'no truncated account address (e.g. "GCDVNXYD...6SE75S") is visible');

  const testnetVisible = await page.getByText('TESTNET', { exact: true }).isVisible().catch(() => false);
  assert(testnetVisible, 'network indicator does not show "TESTNET"');

  log.info('OK: connected, address shown, network is TESTNET');
}
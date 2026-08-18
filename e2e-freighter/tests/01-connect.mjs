// Wallet connect smoke test.
//
// By the time run() is called, the runner has already unlocked Freighter
// and called connectApp() — which itself exercises Freighter's grant-access
// approval path (auto-approved when APPROVE=auto; the popup is optional).
// This test's job is
// just to assert the connected end state is what it actually looks like in
// the app, proving the whole launch -> unlock -> connect pipeline works.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { gotoDashboard } from '../src/navigation.mjs';

const log = createLogger('01-connect');

export async function run({ page }) {
  await gotoDashboard(page);
  // After a successful connect the wallet button is hidden and the address
  // text replaces it in the settings button. These elements already have stable
  // ids, so use them directly instead of adding redundant data-testid attrs.
  const connectBtnVisible = await page
    .locator('#wallet-btn')
    .isVisible()
    .catch(() => false);
  assert(!connectBtnVisible, '"Connect Freighter" button is still visible after connecting');

  const walletText = await page
    .locator('#wallet-text')
    .textContent()
    .catch(() => '');
  const walletTextContent = (walletText || '').trim();
  // The app renders Utils.shortAddress(address, 8, 6) -> first 8 chars + "..." + last 6.
  const addressVisible = /^G[A-Z2-7]{7}\.{3}[A-Z2-7]{6}$/.test(walletTextContent);
  assert(addressVisible, `no truncated account address (e.g. "GCDVNXYD...6SE75S") is visible; got "${walletTextContent}"`);

  const networkName = await page
    .locator('#network-name')
    .textContent()
    .catch(() => '');
  assert((networkName || '').trim() === 'TESTNET', 'network indicator does not show "TESTNET"');

  log.info('OK: connected, address shown, network is TESTNET');
}

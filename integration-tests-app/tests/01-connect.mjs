// Wallet connect smoke test.
//
// By the time run() is called, the runner has already unlocked Freighter
// and called connectApp() — which itself exercises Freighter's grant-access
// approval path (auto-approved when APPROVE=auto; the popup is optional).
// This test's job is
// just to assert the connected end state is what it actually looks like in
// the app, proving the whole launch -> unlock -> connect pipeline works.

import { readFile } from 'node:fs/promises';
import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { gotoDashboard } from '../src/navigation.mjs';

const knownNetworks = JSON.parse(await readFile(new URL('../../sdk/native/src/network_defaults.json', import.meta.url), 'utf8'));

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

  // The badge derives a known network's label from its passphrase,
  // falling back to the deployment folder name for custom networks.
  const deployment = await page.evaluate(async () => {
    const response = await fetch(new URL('./deployments.json', document.baseURI));
    if (!response.ok) {
      throw new Error(`Cannot load deployment config: HTTP ${response.status}`);
    }
    return response.json();
  });
  const configuredName = (Object.hasOwn(knownNetworks, deployment.networkPassphrase)
    ? knownNetworks[deployment.networkPassphrase].displayName : deployment.network);
  assert(typeof configuredName === 'string' && configuredName.trim(),
    'deployment config has no network label');
  const expectedNetworkName = configuredName.toUpperCase().trim();
  const networkName = await page
    .locator('#network-name')
    .textContent()
    .catch(() => '');
  assert(
    (networkName || '').trim() === expectedNetworkName,
    `network indicator should show "${expectedNetworkName}"; got "${(networkName || '').trim()}"`,
  );

  log.info(`OK: connected, address shown, network is ${expectedNetworkName}`);
}

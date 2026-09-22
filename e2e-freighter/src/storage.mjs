// Shared encrypted-storage setup and unlock for the real Freighter suite.
// The test password is derived from the throwaway Freighter test password;
// the application still generates its own random database key.

import { createHash } from 'node:crypto';
import { assert } from './assert.mjs';

export function testDatabasePassword() {
  const walletPassword = process.env.E2E_FREIGHTER_PASSWORD;
  if (!walletPassword) throw new Error('E2E_FREIGHTER_PASSWORD is required for the encrypted test database');
  return createHash('sha256').update('spp/freighter-e2e/database-password/v1\0').update(walletPassword).digest('base64url');
}

export async function unlockStorage(page, context, approveOrWatch, { allowPlaintext = false } = {}) {
  const selection = await page.evaluate(() => localStorage.getItem('spp.storage-access.v1'));
  if (selection === null) {
    if (allowPlaintext) return; // Only the initial provisioning connection is plaintext.
    throw new Error('Freighter E2E requires an encrypted profile; rebuild its snapshot with e2e-freighter/scripts/setup.sh --force');
  }
  const dialog = page.locator('dialog.storage-dialog');
  await dialog.waitFor({ state: 'visible', timeout: 30_000 });
  const wallet = page.locator('#storage-wallet');
  if (!(await wallet.isVisible())) {
    throw new Error(`Encrypted profile cannot use Freighter unlock: ${await page.locator('#storage-feedback').textContent()}`);
  }
  await wallet.click();
  await approveOrWatch(context, 'signMessage', { label: 'unlock encrypted e2e database' });
  await dialog.waitFor({ state: 'hidden', timeout: 60_000 });
}

export async function encryptProvisionedProfile(page, context, approveOrWatch) {
  const password = testDatabasePassword();
  const url = new URL(page.url());
  url.searchParams.set('storage', 'encrypted');
  await page.goto(url.href);
  const dialog = page.locator('dialog.storage-dialog');
  await dialog.waitFor({ state: 'visible', timeout: 30_000 });
  await page.locator('#storage-migrate').waitFor({ state: 'visible' });
  await page.locator('#storage-password').fill(password);
  await page.locator('#storage-confirm').fill(password);
  await page.locator('#storage-migrate').click();
  await page.locator('#storage-feedback').filter({ hasText: 'Encrypted copy verified' }).waitFor({ timeout: 60_000 });

  await page.locator('#storage-password').fill(password);
  const backup = page.waitForEvent('download');
  await page.locator('#storage-backup').click();
  assert((await backup).suggestedFilename() === 'spp-encrypted-key-backup.json', 'test database key backup did not start');
  await page.locator('#storage-migration-confirm').check();
  await page.locator('#storage-password').fill(password);
  await page.locator('#storage-migration-activate').click();
  await page.locator('#storage-feedback').filter({ hasText: 'Migration complete' }).waitFor({ timeout: 60_000 });
  await page.locator('#storage-password').fill(password);
  await page.locator('#storage-unlock').click();
  await dialog.waitFor({ state: 'hidden', timeout: 60_000 });
  await page.locator('#wallet-text').filter({ hasText: /^G[A-Z2-7]{7}\.\.\.[A-Z2-7]{6}$/ }).waitFor({ timeout: 60_000 });

  await page.locator('#open-settings-btn').click();
  await page.getByRole('button', { name: 'Database security' }).click();
  await dialog.waitFor({ state: 'visible' });
  await page.locator('#storage-password').fill(password);
  await page.locator('#storage-wallet-enroll').click();
  await approveOrWatch(context, 'signMessage', { label: 'enroll storage wallet (1/2)' });
  await approveOrWatch(context, 'signMessage', { label: 'enroll storage wallet (2/2)' });
  await page.locator('#storage-feedback').filter({ hasText: 'Wallet unlock added' }).waitFor({ timeout: 30_000 });
  await page.locator('#storage-dismiss').click();
  await page.locator('#settings-close-btn').click();
}

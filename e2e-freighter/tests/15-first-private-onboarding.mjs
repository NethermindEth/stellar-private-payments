import { assert } from '../src/assert.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { driveWizard } from '../src/onboarding.mjs';
export { prepare, connectionOptions } from './14-first-public-connect.mjs';

export async function run({ page, context, connectApp, ...wallet }) {
  assert(await page.locator('#onboarding-modal').isVisible(), 'First connection must show onboarding');
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'Password must not precede onboarding');
  await driveWizard(page, context, wallet);
  assert(await page.locator('body').getAttribute('data-wallet-state') === 'ready', 'Private account setup did not complete');
  assert(await page.locator('#storage-lock-btn').getAttribute('data-state') === 'unlocked', 'Private storage was not unlocked');
  assert(await page.locator('input[type="password"]').count() === 0, 'App must have no password controls');
  await page.locator('#storage-lock-btn').click();
  await page.waitForLoadState('domcontentloaded');
  await waitForCondition({
    operation: 'locked-reload:public-ready', timeoutMs: 60_000,
    observe: () => page.locator('body').getAttribute('data-wallet-state'),
    isReady: state => state === 'locked',
  });
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'Locking must not reopen the unlock dialog');
  assert(!await page.locator('#onboarding-modal').isVisible(), 'Locking must not reopen onboarding');
  await page.locator('#open-settings-btn').click();
  await page.getByTestId('settings-delete-local-data').click();
  await page.getByTestId('confirm-dialog').waitFor();
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'Deleting local data must not require unlock');
  await page.getByTestId('confirm-dialog-cancel').click();
  await page.locator('#settings-close-btn').click();

  await connectApp(page, { context, privateAccess: true });
  await driveWizard(page, context, wallet);
  assert(await page.locator('body').getAttribute('data-wallet-state') === 'ready', 'Wallet unlock after reload failed');
  await page.locator('#storage-lock-btn').click();
  await page.waitForLoadState('domcontentloaded');
  await waitForCondition({
    operation: 'locked-delete:ready', timeoutMs: 60_000,
    observe: () => page.locator('body').getAttribute('data-wallet-state'),
    isReady: state => state === 'locked',
  });
  await page.locator('#open-settings-btn').click();
  await page.getByTestId('settings-delete-local-data').click();
  await Promise.all([
    page.waitForEvent('domcontentloaded'),
    page.getByTestId('confirm-dialog-confirm').click(),
  ]);
  await waitForCondition({
    operation: 'deleted:public-ready', timeoutMs: 60_000,
    observe: () => page.locator('body').getAttribute('data-wallet-state'),
    isReady: state => state === 'locked',
  });
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'Reset must not force immediate setup');
  await page.locator('#storage-lock-btn').click();
  await page.getByTestId('storage-wallet-dialog').waitFor();
  assert(await page.getByTestId('storage-wallet-dialog').getAttribute('data-mode') === 'new', 'Locked deletion must remove the vault and wallet record');
  console.log('OK: Freighter onboarding and explicit unlock; locking opens no dialogs; locked Settings supports cancellation and confirmed local-data deletion');
}

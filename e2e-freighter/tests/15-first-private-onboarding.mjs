import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';
export { prepare, connectionOptions } from './14-first-public-connect.mjs';

export async function run({ page, context, ...wallet }) {
  assert(await page.locator('#onboarding-modal').isVisible(), 'First connection must show onboarding');
  assert(!await page.getByTestId('storage-password-dialog').isVisible(), 'Password must not precede onboarding');
  await driveWizard(page, context, wallet);
  assert(await page.locator('body').getAttribute('data-wallet-state') === 'ready', 'Private account setup did not complete');
  assert(await page.locator('#storage-lock-btn').getAttribute('data-state') === 'unlocked', 'Private storage was not unlocked');
  console.log('OK: first-run onboarding creates protected storage and derives keys through real Freighter');
}

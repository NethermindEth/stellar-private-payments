// Cancelling onboarding while a step is genuinely pending must close the
// modal and leave the app asking to connect again -- not hang.
//
// Does not cover a network change/unreadable wallet cancelling the wizard --
// that needs a third Freighter identity or a network switch this harness
// can't provision. Covered instead by test 14 (same underlying detection).

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { isOnboardingWizardVisible } from '../src/appState.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('17-cancel-onboarding');

const FRESH_LABEL = 'Account 3';

export async function run({ page, context, connectApp, waitForFreighterApproval, approveOrWatch }) {
  const logTag = '17-cancel-onboarding';

  await switchFreighterAccount(context, FRESH_LABEL);
  await connectApp(page, { context });

  const wizardVisible = await isOnboardingWizardVisible(page);
  assert(
    wizardVisible,
    `setup: connecting as ${FRESH_LABEL} did not open the onboarding wizard -- ` +
    'the fresh-account precondition this test needs is not present.',
  );

  await waitForCondition({
    operation: 'onboarding:pending-step-before-cancel',
    timeoutMs: 5000,
    intervalMs: 100,
    observe: async () => ({
      buttons: await page.$$eval('#onboarding-modal button', (els) => els.map((el) => el.textContent.trim()).filter(Boolean)),
    }),
    isReady: ({ buttons }) => buttons.length > 0,
  });
  log.info('a pending onboarding step is on screen -- cancelling now');

  await page.locator('#onboarding-close-btn').click({ force: true });

  const hidden = await waitForCondition({
    operation: 'onboarding:cancel-hides-modal',
    timeoutMs: 5000,
    intervalMs: 100,
    observe: async () => page.evaluate(
      () => document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true,
    ),
    isReady: (isHidden) => isHidden === true,
  }).then((result) => result.value).catch(() => false);
  assert(hidden, 'clicking the onboarding close control did not hide the modal within 5s -- the wizard hung.');

  const connectVisible = await page.locator('#wallet-btn').isVisible().catch(() => false);
  assert(connectVisible, 'onboarding was cancelled but the app never restored the "Connect Freighter" control.');

  log.info('OK: cancelling a pending onboarding step closed the modal and restored the connect control');
}

// Drives the app's real onboarding wizard end to end, for an account that
// was funded and imported into Freighter but never pre-seeded (every other
// test skips this via seedDriverOnboarding — see src/testAccount.mjs and
// src/runner.mjs). This is the one test that proves the wizard itself works.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';

export const rawOnboarding = true;

const log = createLogger('13-onboarding');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;

  const stillVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  assert(stillVisible, 'onboarding wizard did not open for an unseeded account');

  await driveWizard(page, context, {
    waitForFreighterApproval,
    approveOrWatch,
    logTag: '13-onboarding',
  });

  const wizardClosed = await page.evaluate(
    () => document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true,
  );
  assert(wizardClosed, 'onboarding modal still visible after driving all its steps');

  await page.click('[data-view="move-funds"]');
  await page.locator('#btn-deposit').waitFor({ state: 'visible', timeout: 15_000 });

  log.info('OK: onboarding wizard completed, deposit form reachable');
}

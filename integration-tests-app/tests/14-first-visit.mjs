// A first visit, before any wallet connects: the app explains itself, offers
// one action (Connect), shows no Unlock, keeps Disclosure verification usable,
// and turns into the normal app once onboarding finishes.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { requireAppUrl } from '../src/env.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import {
  isOnboardingWizardVisible,
  readAccessState,
  waitForAccessState,
  waitForAppShell,
  waitForWalletRuntimeReady,
} from '../src/appState.mjs';
import { gotoDisclosure } from '../src/navigation.mjs';
import { assertPendingAccess } from '../src/access.mjs';

// No store exists yet, so the app must greet a new user.
export const rawOnboarding = true;
export const connectFirst = false;

const log = createLogger('14-first-visit');

export async function run({ page, context, connectApp, waitForFreighterApproval, approveOrWatch }) {
  await page.goto(requireAppUrl());
  await waitForAppShell(page);
  await waitForAccessState(page, 'welcome');

  await assertPendingAccess(page, { action: 'connect' });
  await gotoDisclosure(page);
  assert(!(await page.getByTestId('access-card').isVisible()), 'the access card covers Disclosure verification on a first visit');

  await page.getByTestId('nav-dashboard').click();
  await connectApp(page);
  assert(await isOnboardingWizardVisible(page), 'onboarding did not open after the first connect');
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '14-first-visit' });
  await waitForWalletRuntimeReady(page);

  assert(await readAccessState(page) === 'ready', `access state after onboarding is "${await readAccessState(page)}"`);
  assert(!(await page.getByTestId('access-card').isVisible()), 'the access card is still shown after onboarding');
  assert(await page.getByTestId('view-dashboard').isVisible(), 'Overview is not shown after onboarding');
  assert(await page.getByTestId('storage-lock-btn').isVisible(), 'no lock control once storage is open');

  log.info('OK: welcome state, then onboarding into the app');
}

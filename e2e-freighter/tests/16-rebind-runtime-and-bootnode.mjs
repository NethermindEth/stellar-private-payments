// A mid-wizard account switch must leave the app fully usable for the
// account switched TO, including that account's own bootnode configuration.
// Reuses test 12's switch choreography.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { isOnboardingWizardVisible, readWalletState } from '../src/appState.mjs';
import { switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('16-rebind-runtime-and-bootnode');

const CONNECT_LABEL = 'Account 3'; // active when onboarding begins; not onboarded
const CHOSEN_LABEL = 'Account 2'; // the account the user switches to mid-wizard

// Distinctive and syntactically valid (the save handler requires https://),
// but not a real archive -- nothing in this test submits a request to it.
const TEST_BOOTNODE_URL = 'https://e2e-16-rebind-bootnode.invalid/archive';

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`16-rebind-runtime-and-bootnode: ${name} is not set`);
  return value;
}

export async function run({ page, context, connectApp, waitForFreighterApproval, approveOrWatch }) {
  const logTag = '16-rebind-runtime-and-bootnode';
  const chosenAddress = requireEnv('E2E_ACCOUNT_C_ADDRESS');

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });

  await switchFreighterAccount(context, CONNECT_LABEL);
  await connectApp(page, { context });
  const wizardVisible = await isOnboardingWizardVisible(page);
  assert(
    wizardVisible,
    `setup: connecting as ${CONNECT_LABEL} did not open the onboarding wizard -- ` +
    'the snapshot precondition this test needs (an un-onboarded second account) is not present.',
  );

  let switchedAtStep = null;
  let sawRetentionStep = false;
  await driveWizard(page, context, {
    waitForFreighterApproval,
    approveOrWatch,
    logTag,
    waitForRuntimeReady: false,
    onStep: async ({ step, choice }) => {
      if (switchedAtStep === null) {
        log.info(`switching to ${CHOSEN_LABEL} before wizard step ${step} ("${choice}")`);
        await switchFreighterAccount(context, CHOSEN_LABEL);
        switchedAtStep = step;
        return;
      }
      if (choice === 'Save retention setup') {
        sawRetentionStep = true;
        await page.locator('#wizard-bootnode-enabled').check();
        await page.locator('#wizard-bootnode-url').fill(TEST_BOOTNODE_URL);
      }
    },
  });
  assert(switchedAtStep !== null, 'setup: the mid-wizard switch hook never fired.');
  log.info(sawRetentionStep
    ? 'retention step appeared for the switched-to account and was filled in'
    : 'retention step did not appear for the switched-to account (already satisfied in the snapshot) -- ' +
      'the bootnode round-trip assertion below is skipped, everything else still applies');

  await connectApp(page, { context });
  const lifecycle = await readWalletState(page);
  assert(
    lifecycle === 'ready',
    `after the mid-wizard switch and a reconnect as ${CHOSEN_LABEL}, the app lifecycle is ` +
    `'${lifecycle}', not 'ready' -- the account switched TO is not left in a working state.`,
  );

  if (sawRetentionStep) {
    const savedUrl = await page.locator('#settings-bootnode-url').inputValue().catch(() => null);
    assert(
      savedUrl === TEST_BOOTNODE_URL,
      `the bootnode URL saved during the switched-to account's retention step did not round-trip: ` +
      `expected '${TEST_BOOTNODE_URL}', settings drawer shows '${savedUrl}'. Either the write landed ` +
      `under the wrong account, or the runtime was not correctly re-initialized for ` +
      `${CHOSEN_LABEL}, so its stored setting was never read back.`,
    );
  }

  log.info(`OK: after a mid-wizard switch to ${chosenAddress}, the app is ready and usable for that account` +
    (sawRetentionStep ? ', and its retention-step bootnode write round-tripped' : ''));
}

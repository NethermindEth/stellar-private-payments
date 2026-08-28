// A genuinely first-time account must be able to complete onboarding.
// Regression test: no existing spec exercised a fresh account's disclaimer
// step to completion (test 12 switches away before it resolves).

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { isOnboardingWizardVisible, readKeyBinding, readWalletState } from '../src/appState.mjs';
import { switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('15-fresh-onboarding');

// Freighter label from scripts/provision.sh --add-account; never granted
// this origin in the base snapshot.
const FRESH_LABEL = 'Account 3';

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`15-fresh-onboarding: ${name} is not set`);
  return value;
}

export async function run({ page, context, connectApp, waitForFreighterApproval, approveOrWatch }) {
  const logTag = '15-fresh-onboarding';
  const freshAddress = requireEnv('E2E_ACCOUNT_D_ADDRESS');

  await switchFreighterAccount(context, FRESH_LABEL);
  log.info('switched Freighter to', FRESH_LABEL, '- reconnecting the app as it');
  await connectApp(page, { context });

  const wizardVisible = await isOnboardingWizardVisible(page);
  assert(
    wizardVisible,
    `setup: connecting as ${FRESH_LABEL} (${freshAddress}) did not open the onboarding wizard. ` +
    `The snapshot is expected to hold ${FRESH_LABEL} as never having been through the app's wizard.`,
  );
  log.info('onboarding wizard open for a fresh account -- driving it to completion');

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });

  const lifecycle = await readWalletState(page);
  assert(
    lifecycle === 'ready',
    `onboarding for a fresh account finished but the app lifecycle is '${lifecycle}', not 'ready'.`,
  );

  const binding = await readKeyBinding(page);
  assert(
    binding.address === freshAddress,
    `onboarding completed under the wrong address: expected ${freshAddress} (${FRESH_LABEL}), ` +
    `got ${binding.address}.`,
  );
  assert(
    !!binding.notePublicKey && !!binding.encryptionPublicKey,
    'onboarding reached "ready" but the app never rendered derived privacy keys ' +
    `(note=${binding.notePublicKey}, enc=${binding.encryptionPublicKey}).`,
  );

  log.info('OK: a fresh account completed onboarding end to end, keys bound to', binding.address);
}

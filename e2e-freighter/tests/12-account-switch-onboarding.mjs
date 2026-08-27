// Switching the Freighter account mid-onboarding must bind the derived privacy
// keys to the account the user switched TO.
//
// The wizard receives the address by value from Wallet.connect(), and the
// disclaimer write, key derivation and registration all consume that same
// binding — so the key assertions below cover all three paths.
//
// The snapshot's active account (Account 2) has already been onboarded, so the
// test starts as the un-onboarded Account 3 and switches to Account 2. Account
// 2 already owns a known key pair, so the expected values are read live at the
// start of the run rather than hard-coded.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { isOnboardingWizardVisible, readKeyBinding } from '../src/appState.mjs';
import { switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('12-account-switch-onboarding');

// Freighter labels assigned by scripts/provision.sh --add-account.
const CONNECT_LABEL = 'Account 3'; // active when onboarding begins; NOT onboarded in the app
const CHOSEN_LABEL = 'Account 2'; // the account the user switches to mid-wizard

const ACCOUNT_NAME_SELECTOR = '[data-testid="account-view-account-name"]';

// The settings drawer mirrors App.state verbatim (see src/appState.mjs).
const NOT_CONNECTED_PLACEHOLDER = 'Not connected';
const NO_KEY_PLACEHOLDER = '—';

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`12-account-switch-onboarding: ${name} is not set`);
  return value;
}

/**
 * The app's own account watcher (`startWatcher()`) begins polling the moment
 * the post-onboarding lifecycle reaches `ready`, and disconnects within one
 * 2s tick because the active Freighter account no longer matches
 * `App.state.wallet.address` — which blanks the settings drawer. Reading the
 * binding from the test after the fact is therefore a race. Install an
 * in-page recorder BEFORE the wizard runs that latches the first fully
 * populated binding the app renders, so the value under test cannot be
 * erased before it is observed.
 */
async function installKeyBindingRecorder(page, { notConnected, noKey }) {
  await page.evaluate(({ notConnected: nc, noKey: nk }) => {
    window.__e2eKeyBinding = null;
    const read = (selector) => {
      const text = document.querySelector(selector)?.textContent?.trim();
      return text || null;
    };
    const timer = setInterval(() => {
      const address = read('#settings-wallet-address');
      const notePublicKey = read('#settings-note-key');
      const encryptionPublicKey = read('#settings-enc-key');
      if (address && address !== nc && notePublicKey && notePublicKey !== nk
        && encryptionPublicKey && encryptionPublicKey !== nk) {
        window.__e2eKeyBinding = { address, notePublicKey, encryptionPublicKey };
        clearInterval(timer);
      }
    }, 50);
  }, { notConnected, noKey });
}

async function readRecordedKeyBinding(page) {
  return page.evaluate(() => window.__e2eKeyBinding || null).catch(() => null);
}

export async function run({ page, context, connectApp, waitForFreighterApproval, approveOrWatch }) {
  const logTag = '12-account-switch-onboarding';
  const connectAccountAddress = requireEnv('E2E_ACCOUNT_D_ADDRESS');
  const chosenAccountAddress = requireEnv('E2E_ACCOUNT_C_ADDRESS');

  // ── 1. Establish the expected key material ──────────────────────────────
  // The runner already connected as the snapshot's active account
  // (CHOSEN_LABEL / E2E_ACCOUNT_C). Clear any residual wizard steps exactly
  // as every other test does, then read the keys that account legitimately
  // owns. These are what a correct app must produce at the end of this test.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  const expected = await readKeyBinding(page);
  log.info('reference binding for', CHOSEN_LABEL, '->', expected.address);
  assert(
    expected.address === chosenAccountAddress,
    `setup: expected the runner to connect as ${CHOSEN_LABEL} (${chosenAccountAddress}), ` +
    `but the app is bound to ${expected.address}. The profile snapshot's active account changed.`,
  );
  assert(
    !!expected.notePublicKey && !!expected.encryptionPublicKey,
    `setup: ${CHOSEN_LABEL} has no derived privacy keys in the restored profile, so there is ` +
    'no reference key material to compare against (note=' +
    `${expected.notePublicKey}, enc=${expected.encryptionPublicKey}).`,
  );

  // ── 2. Begin onboarding as the OTHER account ────────────────────────────
  const extensionPage = await switchFreighterAccount(context, CONNECT_LABEL);
  log.info('switched Freighter to', CONNECT_LABEL, '- reconnecting the app as it');
  await connectApp(page, { context });

  const wizardVisible = await isOnboardingWizardVisible(page);
  assert(
    wizardVisible,
    `setup: connecting as ${CONNECT_LABEL} (${connectAccountAddress}) did not open the onboarding ` +
    'wizard, so this run never reached a first-time onboarding state. The snapshot is expected to ' +
    `hold ${CONNECT_LABEL} as an account that has NOT been through the app's wizard.`,
  );
  log.info('onboarding wizard is open for', CONNECT_LABEL);

  // ── 3. Switch accounts mid-wizard, then finish onboarding ───────────────
  await installKeyBindingRecorder(page, {
    notConnected: NOT_CONNECTED_PLACEHOLDER,
    noKey: NO_KEY_PLACEHOLDER,
  });

  let switchedAtStep = null;
  await driveWizard(page, context, {
    waitForFreighterApproval,
    approveOrWatch,
    logTag,
    // The app's own account watcher disconnects the wallet within one 2s
    // tick of onboarding finishing, because the active Freighter account no
    // longer matches the address it connected as. Waiting for a settled
    // `ready` lifecycle here is therefore a race the test can lose — and
    // losing it produces a readiness timeout instead of this test's own
    // assertion. The recorder below is the signal that actually matters.
    waitForRuntimeReady: false,
    onStep: async ({ step, choice }) => {
      if (switchedAtStep !== null) return;
      // Switch before the very first step resolves, so every wizard write —
      // the disclaimer, the key derivation and any registration — happens
      // while the user is looking at CHOSEN_LABEL.
      log.info(`switching to ${CHOSEN_LABEL} before wizard step ${step} ("${choice}")`);
      await switchFreighterAccount(context, CHOSEN_LABEL);
      switchedAtStep = step;
    },
  });

  assert(
    switchedAtStep !== null,
    'setup: the mid-wizard hook never fired, so no account switch happened during onboarding.',
  );

  // Prove the switch actually took and stayed, so a later mismatch cannot be
  // blamed on the wallet quietly reverting.
  const activeAfterWizard = await waitForCondition({
    operation: 'freighter:active-account-after-wizard',
    timeoutMs: 10_000,
    intervalMs: 200,
    observe: async () => (await extensionPage.locator(ACCOUNT_NAME_SELECTOR).innerText().catch(() => '')).trim(),
    isReady: (name) => name === CHOSEN_LABEL,
  }).then((result) => result.value).catch(() => null);
  assert(
    activeAfterWizard === CHOSEN_LABEL,
    `setup: expected ${CHOSEN_LABEL} to still be the active Freighter account after onboarding, ` +
    `but the extension reports '${activeAfterWizard}'. The mid-wizard switch did not hold.`,
  );

  // ── 4. Which account do the onboarding results belong to? ───────────────
  // `Wallet.connect()` renders the settings drawer from App.state right after
  // it derives and loads the keys, and before it flips the lifecycle to
  // `ready` and starts the watcher that will disconnect. The recorder latches
  // that render; waiting for it is what makes the observation deterministic.
  const recorded = await waitForCondition({
    operation: 'app:key-binding-recorded',
    timeoutMs: 60_000,
    intervalMs: 200,
    observe: () => readRecordedKeyBinding(page),
    isReady: (binding) => binding !== null,
  }).then((result) => result.value).catch(() => null);
  const observed = recorded || (await readKeyBinding(page));
  log.info('binding after onboarding:', JSON.stringify(observed));

  assert(
    !!observed.notePublicKey && !!observed.encryptionPublicKey,
    'onboarding finished but the app never rendered a derived note/encryption key pair within 60s ' +
    `(note=${observed.notePublicKey}, enc=${observed.encryptionPublicKey}), so which account ` +
    'they belong to cannot be judged. This is a harness/app-startup failure, not the defect ' +
    'under test.',
  );

  // The headline assertion. The user finished onboarding while CHOSEN_LABEL
  // was selected, so the keys the app derived and stored must be that
  // account's.
  assert(
    observed.notePublicKey === expected.notePublicKey,
    `onboarding derived the note public key for the CONNECT-TIME account instead of the one ` +
    `the user switched to.\n` +
    `  expected (${CHOSEN_LABEL}, ${chosenAccountAddress}): ${expected.notePublicKey}\n` +
    `  observed:                                            ${observed.notePublicKey}\n` +
    `  (${CONNECT_LABEL} = ${connectAccountAddress} was active when Wallet.connect() read the address; ` +
    `the switch to ${CHOSEN_LABEL} happened at wizard step ${switchedAtStep})`,
  );
  assert(
    observed.encryptionPublicKey === expected.encryptionPublicKey,
    `onboarding derived the encryption public key for the CONNECT-TIME account instead of the ` +
    `one the user switched to.\n` +
    `  expected (${CHOSEN_LABEL}): ${expected.encryptionPublicKey}\n` +
    `  observed:                   ${observed.encryptionPublicKey}`,
  );
  // `address` is the single value the wizard also hands to
  // storage.acceptDisclaimer() and registerNow(), so this covers the
  // disclaimer and registration bindings too.
  assert(
    observed.address === chosenAccountAddress,
    `the app's onboarding wrote everything (disclaimer, stored keys, any registration) under ` +
    `the connect-time address.\n` +
    `  expected: ${chosenAccountAddress} (${CHOSEN_LABEL}, the account the user switched to)\n` +
    `  observed: ${observed.address}`,
  );

  log.info('OK: onboarding bound the derived keys to the account the user switched to');
}

// Switching to a Freighter account that has not granted this origin must end
// the session rather than leave it live under the previous identity.
//
// Separate from test 13 because the rule lives in wallet-session-policy.js and
// both pages use it. Test 12 does not cover this: it reconnects as the new
// account, so the origin is granted and the wallet stays readable. This one
// deliberately does not grant.
//
// With no grant, WatchWalletChanges cannot return an address and reports an
// unreadable wallet rather than an account change. The session ends after
// UNREADABLE_POLL_LIMIT consecutive unreadable polls, which is why the wait
// below is generous.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { gotoDashboard } from '../src/navigation.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { readWalletState, waitForWalletRuntimeReady } from '../src/appState.mjs';
import { switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('14-unreadable-wallet-main-app');

// The snapshot's active account (already granted) and the account that is
// present in Freighter but has NOT granted this origin. Same pair as test 12,
// used in the opposite direction and without the reconnect.
const UNGRANTED_LABEL = 'Account 3';

export async function run({ page, context, waitForFreighterApproval, approveOrWatch }) {
  const logTag = '14-unreadable-wallet-main-app';
  await gotoDashboard(page);

  // The runner already connected as the snapshot's active account. Clear any
  // residual wizard steps the way every other test does, then get to a settled
  // 'ready' lifecycle so the watcher is running and past onboarding.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await waitForWalletRuntimeReady(page);
  const before = await readWalletState(page);
  assert(before === 'ready', `setup: expected a ready wallet lifecycle before switching; got '${before}'`);

  // Switch WITHOUT reconnecting. No approval is requested and none is given —
  // that is the condition being tested, not an oversight.
  await switchFreighterAccount(context, UNGRANTED_LABEL);
  await page.bringToFront();
  log.info(`switched to ${UNGRANTED_LABEL} without granting this origin`);

  const settled = await waitForCondition({
    operation: 'app:unreadable-wallet-ends-session',
    // Three unreadable polls at 2s, plus room for the extension to settle
    // after the switch.
    timeoutMs: 30_000,
    intervalMs: 250,
    observe: () => readWalletState(page),
    isReady: (value) => value === 'disconnected',
  }).then((result) => result.value);

  assert(
    settled === 'disconnected',
    `the app stayed '${settled}' after the active account moved to one it cannot read; ` +
    'it was still offering wallet-bound actions under the previously connected identity',
  );

  // The session is over, so the app must be asking to connect again rather
  // than still displaying the old account.
  const connectVisible = await page.locator('#wallet-btn').isVisible().catch(() => false);
  assert(connectVisible, 'the app disconnected but never restored the "Connect Freighter" control');

  log.info('OK: an unreadable wallet ended the main-app session and restored the connect control');
}

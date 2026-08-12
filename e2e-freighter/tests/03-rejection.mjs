// Rejection path: start a deposit, reject the signTransaction approval in
// Freighter, and assert the app recovers cleanly — no stuck "Signing…"
// indicator, and the outcome is surfaced as a user cancellation, not a
// generic error or a crash.
//
// This exercises the app's cancellation classifier end to end
// (app/js/ui/errors.js's isUserCancelledError / getTransactionErrorMessage).
// Per sdk/web/src/signer.rs's wallet_js_error comment, the classifier
// prefers Freighter's structured SEP-0043 `code: -4` and only falls back to
// substring-matching the wallet's own message — so a real Freighter
// rejection (this test) is what actually proves that path, not a mocked
// error object.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('03-rejection');



export async function run({ page, context, waitForFreighterApproval, approveOrWatch, rejectInFreighter }) {
  // Wizard state is per-origin: drive it on fresh origins, no-op elsewhere.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '03-rejection' });
  // Bare APP_URL lands on Overview; Move Funds controls are hidden until
  // the tab is opened.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const balanceLocator = page.locator('#move-funds-balance');
  await balanceLocator.waitFor({ state: 'visible', timeout: 15000 });
  // Only needs to not be the loading placeholder — this test doesn't touch
  // balance afterwards, unlike 02-deposit's accumulation assertion.
  const readyDeadline = Date.now() + 15000;
  while ((await balanceLocator.innerText()).trim() === '—' && Date.now() < readyDeadline) {
    await page.waitForTimeout(300);
  }

  await page.fill('#deposit-amount', '0.01');

  const depositBtn = page.locator('#btn-deposit');
  await depositBtn.click();

  // Same runtime confirmation dialog 02-deposit found (not in this
  // checkout's app/js source — a build/deploy drift).
  const confirmDialog = page.getByRole('dialog').filter({ hasText: 'Confirm deposit' });
  const dialogAppeared = await confirmDialog
    .waitFor({ state: 'visible', timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (dialogAppeared) {
    await confirmDialog.getByRole('button', { name: 'Deposit', exact: true }).click();
  }

  await waitForFreighterApproval(context, 'signTransaction', { timeoutMs: 60000 });
  await rejectInFreighter(context, 'signTransaction', { timeoutMs: 15000 });

  // Assert the toast wording the classifier is documented to depend on —
  // exact wording is load-bearing here per signer.rs's comment.
  const toastLocator = page.getByText('Deposit cancelled.', { exact: true });
  const toastAppeared = await toastLocator
    .waitFor({ state: 'visible', timeout: 15000 })
    .then(() => true)
    .catch(() => false);
  assert(
    toastAppeared,
    `expected a "Deposit cancelled." toast after rejecting; got: "${await page.locator('#toast-container').innerText().catch(() => '(none)')}"`,
  );

  // Assert idle-state recovery: no stuck "Signing…"/"Proving…" indicator,
  // button re-enabled, back to its normal "Deposit" label.
  const loadingHidden = await depositBtn.locator('.btn-loading').isHidden().catch(() => false);
  assert(loadingHidden, 'deposit button is still showing a progress indicator after rejection — recovery UX did not reset it');

  const stillDisabled = await depositBtn.isDisabled().catch(() => true);
  assert(!stillDisabled, 'deposit button is still disabled after rejection — recovery UX did not reset it');

  const textVisible = await depositBtn.locator('.btn-text').isVisible().catch(() => false);
  assert(textVisible, "deposit button's normal label is not visible after rejection recovery");

  log.info('OK: rejected deposit surfaced as "Deposit cancelled." and the app returned to idle');
}
// Rejection path: reject a real Freighter signTransaction approval and prove
// the app classifies it as a user cancellation before returning the control to
// the normal idle state.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { gotoMoveFunds } from '../src/navigation.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { waitForCondition } from '../src/waits.mjs';

const log = createLogger('03-rejection');

export async function run({ page, context, waitForFreighterApproval, approveOrWatch, rejectInFreighter }) {
  const logTag = '03-rejection';
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);
  await page.getByTestId('move-panel-deposit').waitFor({ state: 'visible', timeout: 10_000 });

  await page.locator('#deposit-amount').fill('0.01');
  const depositButton = page.locator('#btn-deposit');
  await depositButton.click();

  // The wallet rejection is the behavior under test; confirm the dialog when
  // the current app exposes it.
  const dialog = page.getByTestId('confirm-dialog');
  const dialogAppeared = await dialog
    .waitFor({ state: 'visible', timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (dialogAppeared) {
    await dialog.getByTestId('confirm-dialog-confirm').click();
  }

  await waitForFreighterApproval(context, 'signTransaction', { timeoutMs: 60_000 });
  await rejectInFreighter(context, 'signTransaction', { timeoutMs: 15_000 });

  const recovery = await waitForCondition({
    operation: 'deposit-rejection-recovery',
    timeoutMs: 15_000,
    observe: async () => ({
      toastVisible: await page.getByText('Deposit cancelled.', { exact: true }).isVisible().catch(() => false),
      loadingVisible: await depositButton.locator('.btn-loading').isVisible().catch(() => false),
      disabled: await depositButton.isDisabled().catch(() => true),
      normalLabelVisible: await depositButton.locator('.btn-text').isVisible().catch(() => false),
    }),
    isReady: ({ toastVisible, loadingVisible, disabled, normalLabelVisible }) => (
      toastVisible && !loadingVisible && !disabled && normalLabelVisible
    ),
  });

  assert(recovery.value.toastVisible, 'expected a "Deposit cancelled." toast after rejecting the wallet approval');
  log.info('OK: rejected deposit surfaced as "Deposit cancelled." and the app returned to idle');
}

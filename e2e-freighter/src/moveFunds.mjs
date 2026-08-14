// Shared "submit one Move Funds transaction and confirm it" machinery.
// Extracted from tests/04-deposit-withdraw.mjs (originally written for
// deposit + withdraw), reused by tests/05-deposit-transfer.mjs (transfer) —
// deposit, withdraw, and transfer all follow the same shape in the deployed
// app: fill an amount field, click a submit button, handle that flow's own
// runtime confirmation dialog (role="dialog", not in this checkout's app/js
// source — a build/deploy drift found by screenshotting live runs), drive
// every sequential Freighter approval, capture the tx hash from the
// success toast's explorer link, then confirm SUCCESS on-chain via
// ./chain.mjs (never trust a UI balance display — see tests/02-deposit.mjs
// for why).

import { createLogger } from './logger.mjs';
import { waitForTransactionSuccess } from './chain.mjs';

const APPROVAL_GRACE_MS = 2000;
const TOAST_POLL_MS = 500;
const PROGRESS_LOG_MS = 2000;

// Fill amount, click submit, handle the runtime confirmation dialog, drive
// every sequential Freighter approval, capture the submitted tx hash from
// the toast's explorer link, then confirm SUCCESS on-chain.
export async function submitAndConfirm(
  { page, context, waitForAnyFreighterApproval, approveOrWatch },
  {
    logTag,
    flowName,
    amountSelector,
    submitSelector,
    confirmDialogTitle,
    confirmButtonLabel,
    amount,
    rpcUrl,
    fillBeforeSubmit,
    progressTimeoutMs = 120000,
  },
) {
  const log = createLogger(`${logTag}/moveFunds`);
  const approve = (kind, opts) => approveOrWatch(context, kind, opts);
  const fail = (message) => {
    throw new Error(`${logTag}: ${message}`);
  };

  // A prior toast (e.g. an earlier leg in the same compound test) can still
  // be visible for a few seconds after its flow finished — capture
  // whatever href is showing right now so this leg only ever accepts a
  // DIFFERENT (i.e. genuinely new) one, never a stale leftover.
  const toastLink = page.locator('#toast-container .toast-link').first();
  const previousHref = await toastLink.getAttribute('href', { timeout: 500 }).catch(() => null);

  if (fillBeforeSubmit) await fillBeforeSubmit();
  await page.fill(amountSelector, amount);
  const submitBtn = page.locator(submitSelector);
  await submitBtn.click();

  const confirmDialog = page.getByRole('dialog').filter({ hasText: confirmDialogTitle });
  const dialogAppeared = await confirmDialog
    .waitFor({ state: 'visible', timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (dialogAppeared) {
    await confirmDialog.getByRole('button', { name: confirmButtonLabel, exact: true }).click();
  }

  log.info(`${flowName}: driving Freighter approvals (deadline ${progressTimeoutMs}ms)`);
  const seenStages = new Set();
  let firstApprovalElapsed = null;
  const pollStart = Date.now();
  const progressDeadline = Date.now() + progressTimeoutMs;
  let approvalsDone = false;

  // Background progress logger: reading the button label is safe; reading
  // the toast link during proving is not.
  const progressInterval = setInterval(async () => {
    try {
      const stageText = await submitBtn.locator('.btn-loading').innerText();
      if (stageText && !seenStages.has(stageText)) {
        seenStages.add(stageText);
        log.info(`${flowName}: progress stage: ${stageText} (elapsed ${Date.now() - pollStart}ms)`);
      }
    } catch {
      // ignore
    }
  }, PROGRESS_LOG_MS);

  try {
    while (Date.now() < progressDeadline) {
      const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
        timeoutMs: APPROVAL_GRACE_MS,
      }).catch(() => null);

      if (!pending) {
        // No approval appeared for the grace period. If we have ever seen a
        // progress stage, the transaction is in flight and approvals are done.
        if (seenStages.size > 0) {
          approvalsDone = true;
          break;
        }
        // Otherwise the deposit hasn't started yet; keep waiting.
        continue;
      }

      if (firstApprovalElapsed === null) {
        firstApprovalElapsed = Date.now() - pollStart;
        log.info(`${flowName}: first Freighter approval detected after ${firstApprovalElapsed}ms: ${pending.kind}`);
      }
      log.info(`${flowName}: driving Freighter approval: ${pending.kind}`);
      await approve(pending.kind, { timeoutMs: 15000, label: pending.kind });
      // Give the just-approved popup a moment to close before the next scan.
      await page.waitForTimeout(500);
    }
  } finally {
    clearInterval(progressInterval);
  }

  if (seenStages.size === 0) {
    fail(`${flowName}: submit button never showed a progress stage — the click may not have started anything`);
  }
  log.debug(flowName, 'progress stages:', [...seenStages].join(' -> '));

  if (!approvalsDone) {
    fail(`${flowName}: timed out waiting for Freighter approvals`);
  }

  log.info(`${flowName}: waiting for success toast`);
  const toastDeadline = Date.now() + 30000;
  let txHash = null;
  while (Date.now() < toastDeadline) {
    const href = await toastLink.getAttribute('href', { timeout: 500 }).catch(() => null);
    if (href && href !== previousHref) {
      txHash = href.split('/').filter(Boolean).pop();
      break;
    }
    await page.waitForTimeout(TOAST_POLL_MS);
  }

  if (!txHash) {
    fail(`${flowName}: no transaction hash was captured from the submitted-transaction toast's explorer link`);
  }
  log.info(flowName, 'captured tx hash:', txHash);

  const status = await waitForTransactionSuccess(txHash, { rpcUrl, timeoutMs: 60000 });
  if (status !== 'SUCCESS') fail(`${flowName}: transaction ${txHash} resolved with status ${status}, not SUCCESS`);
  log.info(flowName, 'tx', txHash, 'confirmed SUCCESS on-chain');

  return txHash;
}

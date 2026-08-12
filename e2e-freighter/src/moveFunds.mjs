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
  const toastLink = page.locator('#toast-container .toast-link:not(.hidden)').first();
  const previousHref = await toastLink.getAttribute('href').catch(() => null);

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

  const seenStages = new Set();
  const progressDeadline = Date.now() + progressTimeoutMs;
  let txHash = null;

  while (Date.now() < progressDeadline) {
    const stageText = await submitBtn.locator('.btn-loading').innerText().catch(() => '');
    if (stageText) seenStages.add(stageText);

    const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
      timeoutMs: 2000,
    }).catch(() => null);
    if (pending) {
      await approve(pending.kind, { timeoutMs: 15000 });
      await page.waitForTimeout(500);
      continue;
    }

    const href = await toastLink.getAttribute('href').catch(() => null);
    if (href && href !== previousHref) {
      txHash = href.split('/').filter(Boolean).pop();
      break;
    }

    const stillLoading = await submitBtn.isDisabled().catch(() => false);
    if (!stillLoading && seenStages.size > 0) {
      const lateHref = await toastLink.getAttribute('href').catch(() => null);
      if (lateHref && lateHref !== previousHref) txHash = lateHref.split('/').filter(Boolean).pop();
      break;
    }

    await page.waitForTimeout(500);
  }

  if (seenStages.size === 0) {
    fail(`${flowName}: submit button never showed a progress stage — the click may not have started anything`);
  }
  log.debug(flowName, 'progress stages:', [...seenStages].join(' -> '));
  if (!txHash) {
    fail(`${flowName}: no transaction hash was captured from the submitted-transaction toast's explorer link`);
  }
  log.info(flowName, 'captured tx hash:', txHash);

  const status = await waitForTransactionSuccess(txHash, { rpcUrl, timeoutMs: 60000 });
  if (status !== 'SUCCESS') fail(`${flowName}: transaction ${txHash} resolved with status ${status}, not SUCCESS`);
  log.info(flowName, 'tx', txHash, 'confirmed SUCCESS on-chain');

  return txHash;
}
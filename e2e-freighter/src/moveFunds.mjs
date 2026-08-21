// Shared transaction operation for deposit, withdrawal, and transfer. It
// fills the form, confirms the flow-specific dialog, handles Freighter
// approvals, captures the transaction hash, and confirms it on-chain.

import { createLogger } from './logger.mjs';
import { confirmTransaction } from './chain.mjs';
import { waitForCondition } from './waits.mjs';

const APPROVAL_GRACE_MS = 2000;
const PROGRESS_LOG_MS = 2000;

async function submittedToasts(page) {
  return page.getByTestId('toast').evaluateAll((toasts) => toasts.map((toast) => ({
    origin: toast.getAttribute('data-toast-origin'),
    transactionHash: toast.getAttribute('data-transaction-hash'),
    state: toast.getAttribute('data-state'),
    message: toast.querySelector('[data-testid="toast-message"]')?.textContent?.trim() || '',
  })));
}

/** Wait for a visible application toast matching an operation-level predicate. */
export async function waitForToast(page, {
  origin,
  predicate = () => true,
  timeoutMs = 10_000,
  waitOptions = {},
} = {}) {
  if (typeof predicate !== 'function') throw new TypeError('waitForToast predicate must be a function');
  const result = await waitForCondition({
    operation: `toast:${origin || 'any'}`,
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => {
      const toasts = await submittedToasts(page);
      const match = [...toasts].reverse().find((toast) => (
        toast.state === 'visible' &&
        (!origin || toast.origin === origin) &&
        predicate(toast)
      ));
      return { match: match || null, toasts };
    },
    isReady: ({ match }) => Boolean(match),
  });
  return result.value.match;
}

/** Wait until an operation control has visibly returned to its idle state. */
export async function waitForOperationIdle(page, {
  submitSelector,
  timeoutMs = 15_000,
  waitOptions = {},
} = {}) {
  if (!submitSelector) throw new TypeError('waitForOperationIdle requires submitSelector');
  const button = page.locator(submitSelector);
  const result = await waitForCondition({
    operation: `operation-idle:${submitSelector}`,
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => ({
      status: await button.getAttribute('data-status').catch(() => 'unknown'),
      disabled: await button.isDisabled().catch(() => true),
      loadingVisible: await button.locator('.btn-loading').isVisible().catch(() => false),
      normalLabelVisible: await button.locator('.btn-text').isVisible().catch(() => false),
    }),
    isReady: ({ status, disabled, loadingVisible, normalLabelVisible }) => (
      status === 'idle' && !disabled && !loadingVisible && normalLabelVisible
    ),
  });
  return result.value;
}

/** Wait for the transfer recipient lookup to reach a particular UI state. */
export async function waitForRecipientLookup(page, {
  expectedText,
  manualVisible,
  statusSelector = '#transfer-lookup-status',
  warningSelector = '#transfer-lookup-warning',
  manualSelector = '#transfer-manual-fields',
  timeoutMs = 15_000,
  waitOptions = {},
} = {}) {
  if (!expectedText) throw new TypeError('waitForRecipientLookup requires expectedText');
  const status = page.locator(statusSelector);
  const warning = page.locator(warningSelector);
  const manual = page.locator(manualSelector);
  const result = await waitForCondition({
    operation: `recipient-lookup:${expectedText}`,
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => ({
      status: (await status.innerText().catch(() => '')).trim(),
      warning: (await warning.innerText().catch(() => '')).trim(),
      manualVisible: await manual.isVisible().catch(() => false),
    }),
    isReady: (state) => (
      state.status.includes(expectedText) &&
      (manualVisible === undefined || state.manualVisible === manualVisible)
    ),
  });
  return result.value;
}

/** Wait until clearing a recipient has reset its lookup UI. */
export async function waitForRecipientLookupReset(page, {
  statusSelector = '#transfer-lookup-status',
  warningSelector = '#transfer-lookup-warning',
  manualSelector = '#transfer-manual-fields',
  timeoutMs = 5_000,
  waitOptions = {},
} = {}) {
  const status = page.locator(statusSelector);
  const warning = page.locator(warningSelector);
  const manual = page.locator(manualSelector);
  const result = await waitForCondition({
    operation: 'recipient-lookup:reset',
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => ({
      status: (await status.innerText().catch(() => '')).trim(),
      warning: (await warning.innerText().catch(() => '')).trim(),
      manualVisible: await manual.isVisible().catch(() => false),
    }),
    isReady: (state) => !state.status && !state.warning && !state.manualVisible,
  });
  return result.value;
}

// Wait for the newly-rendered submitted toast. This deliberately uses the
// production transaction hash marker rather than treating an explorer href as
// the only source of transaction identity.
export async function waitForSubmittedTransaction(page, {
  origin,
  previousHashes = [],
  timeoutMs = 30_000,
  waitOptions = {},
} = {}) {
  const previous = new Set(previousHashes.filter(Boolean));
  const result = await waitForCondition({
    operation: `transaction-toast:${origin || 'any'}`,
    timeoutMs,
    intervalMs: 200,
    ...waitOptions,
    observe: async () => {
      const toasts = await submittedToasts(page);
      const match = [...toasts].reverse().find((toast) => (
        toast.state === 'visible' &&
        (!origin || toast.origin === origin) &&
        toast.transactionHash &&
        !previous.has(toast.transactionHash)
      ));
      return { match: match || null, toasts };
    },
    isReady: ({ match }) => Boolean(match),
  });
  return result.value.match;
}

// Fill amount, click submit, handle the runtime confirmation dialog, drive
// every sequential Freighter approval, capture the submitted tx hash from
// the toast's explorer link, then confirm SUCCESS on-chain.
export async function submitAndConfirmOperation(
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

  const previousHashes = (await submittedToasts(page)).map((toast) => toast.transactionHash);

  if (fillBeforeSubmit) await fillBeforeSubmit();
  if (amountSelector) {
    if (amount === undefined) throw new TypeError(`${flowName}: amount is required when amountSelector is set`);
    await page.fill(amountSelector, amount);
  }
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
  let sawSubmitting = (await submitBtn.getAttribute('data-status').catch(() => 'unknown')) === 'submitting';
  let firstApprovalElapsed = null;
  const pollStart = Date.now();
  const progressDeadline = Date.now() + progressTimeoutMs;
  let operationSettled = false;

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
      const buttonState = await submitBtn.getAttribute('data-status').catch(() => 'unknown');
      if (buttonState === 'submitting') sawSubmitting = true;
      const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
        timeoutMs: APPROVAL_GRACE_MS,
      }).catch(() => null);

      if (!pending) {
        // Proving can precede a later signing prompt. Only stop watching for
        // approvals once the production operation control has returned idle.
        if (sawSubmitting && buttonState === 'idle') {
          operationSettled = true;
          break;
        }
        continue;
      }

      if (firstApprovalElapsed === null) {
        firstApprovalElapsed = Date.now() - pollStart;
        log.info(`${flowName}: first Freighter approval detected after ${firstApprovalElapsed}ms: ${pending.kind}`);
      }
      log.info(`${flowName}: driving Freighter approval: ${pending.kind}`);
      await approve(pending.kind, { timeoutMs: 15000, label: pending.kind });
    }
  } finally {
    clearInterval(progressInterval);
  }

  if (!sawSubmitting) {
    fail(`${flowName}: submit button never left its idle state — the click may not have started anything`);
  }
  log.debug(flowName, 'progress stages:', [...seenStages].join(' -> '));

  if (!operationSettled) {
    const finalState = await submitBtn.getAttribute('data-status').catch(() => 'unknown');
    const finalProgress = await submitBtn.getAttribute('data-progress').catch(() => null);
    fail(`${flowName}: operation did not settle before approval deadline (button state: ${finalState}, progress: ${finalProgress})`);
  }

  log.info(`${flowName}: waiting for submitted transaction toast`);
  const toast = await waitForSubmittedTransaction(page, {
    origin: flowName,
    previousHashes,
    timeoutMs: 30_000,
  }).catch((error) => fail(`${flowName}: ${error.message}`));
  const txHash = toast.transactionHash;
  log.info(flowName, 'captured tx hash:', txHash);

  const confirmation = await confirmTransaction(txHash, { rpcUrl, timeoutMs: 60000 });
  if (confirmation.status !== 'SUCCESS') fail(`${flowName}: transaction ${txHash} resolved with status ${confirmation.status}, not SUCCESS`);
  log.info(flowName, 'tx', txHash, 'confirmed SUCCESS on-chain');

  return { transactionHash: txHash, status: confirmation.status, toast };
}

export function deposit(helpers, options) {
  return submitAndConfirmOperation(helpers, {
    flowName: 'deposit',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    ...options,
  });
}

export function withdraw(helpers, options) {
  return submitAndConfirmOperation(helpers, {
    flowName: 'withdraw',
    amountSelector: '#withdraw-amount',
    submitSelector: '#btn-withdraw',
    confirmDialogTitle: 'Confirm withdrawal',
    confirmButtonLabel: 'Withdraw',
    ...options,
  });
}

export function transfer(helpers, options) {
  return submitAndConfirmOperation(helpers, {
    flowName: 'transfer',
    amountSelector: '#transfer-amount',
    submitSelector: '#btn-transfer',
    confirmDialogTitle: 'Confirm transfer',
    confirmButtonLabel: 'Transfer',
    ...options,
  });
}

export function advancedTransfer(helpers, options) {
  return submitAndConfirmOperation(helpers, {
    flowName: 'advanced',
    submitSelector: '#btn-advanced-transact',
    confirmDialogTitle: 'Confirm advanced transaction',
    confirmButtonLabel: 'Transact',
    progressTimeoutMs: 180_000,
    ...options,
  });
}

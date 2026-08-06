// Compound test: deposit 0.01 XLM, then withdraw 0.01 XLM back to the same
// (connected) wallet. Reuses 02-deposit.mjs's proven machinery — the
// deployed app's runtime confirmation dialog, .btn-loading progress-stage
// tracking, sequential Freighter approval handling, and toast-link hash
// capture + on-chain confirmation via ../src/chain.mjs — parameterized here
// as submitAndConfirm() so both legs share it instead of duplicating it.
//
// Withdraw discovery (not in this checkout's app/js source — same
// build/deploy drift 02-deposit found): switching to the Withdraw tab is
// `[data-move-flow="withdraw"]` (plain text "Withdraw" also matches an
// unrelated hidden quick-flow button elsewhere on the page, so the tab
// needs this more specific selector). Its own runtime dialog is titled
// "Confirm withdrawal" with a "Withdraw" confirm button. Leaving
// #withdraw-recipient blank withdraws to the connected wallet (its
// placeholder says so, and the confirm dialog fills the recipient row with
// the connected address to prove it).
//
// SYNC-WAIT: withdraw needs the just-deposited note to be visible to the
// client before it can build its withdrawal plan. This is NOT gated on
// here with an explicit wait — the SDK's own client (sdk/client/src/sync.rs,
// confirmed via the vendored wasm binary's string table: "sync_wait",
// "Waiting to sync …") retries internally and surfaces its own progress
// stage through the same .btn-loading text this test already tracks
// generically. The deposit's own on-chain SUCCESS confirmation (not a UI
// balance read — see 02-deposit.mjs for why) is started immediately before
// withdrawing; if the SDK's internal retry ever proves insufficient, that
// will show up as a withdraw progress-stage timeout, not a silent wrong
// result.

import { waitForTransactionSuccess } from '../src/chain.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`04-deposit-withdraw: ${message}`);
}

async function assertNoOnboardingWizard(page) {
  const wizardVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (wizardVisible) {
    throw new Error(
      '04-deposit-withdraw: the onboarding wizard rendered on a profile that should be wizard-proof — ' +
        'this invalidates step 1.1\'s premise from the wizard-proof-snapshot plan. ' +
        'Report via `plan deviate` rather than driving the wizard from here.',
    );
  }
}

// Fill amount, click submit, handle the runtime confirmation dialog, drive
// every sequential Freighter approval, capture the submitted tx hash from
// the toast's explorer link, then confirm SUCCESS on-chain. Shared by both
// the deposit and withdraw legs below — only the selectors/labels differ.
async function submitAndConfirm(
  { page, context, waitForAnyFreighterApproval, approveOrWatch },
  { flowName, amountSelector, submitSelector, confirmDialogTitle, confirmButtonLabel, amount, rpcUrl, progressTimeoutMs = 120000 },
) {
  const approve = (kind, opts) => approveOrWatch(context, kind, opts);

  // A prior toast (e.g. the deposit leg's) can still be visible for a few
  // seconds after its flow finished — capture whatever href is showing
  // right now so this leg only ever accepts a DIFFERENT (i.e. genuinely
  // new) one, never a stale leftover from an earlier submission.
  const toastLink = page.locator('#toast-container .toast-link:not(.hidden)').first();
  const previousHref = await toastLink.getAttribute('href').catch(() => null);

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

  assert(seenStages.size > 0, `${flowName}: submit button never showed a progress stage — the click may not have started anything`);
  console.log(`[04-deposit-withdraw] ${flowName} progress stages seen: ${[...seenStages].join(' -> ')}`);
  assert(txHash, `${flowName}: no transaction hash was captured from the submitted-transaction toast's explorer link`);
  console.log(`[04-deposit-withdraw] ${flowName} captured transaction hash: ${txHash}`);

  const status = await waitForTransactionSuccess(txHash, { rpcUrl, timeoutMs: 60000 });
  assert(status === 'SUCCESS', `${flowName}: transaction ${txHash} resolved with status ${status}, not SUCCESS`);
  console.log(`[04-deposit-withdraw] ${flowName} transaction ${txHash} confirmed SUCCESS on-chain`);

  return txHash;
}

export async function run(helpers) {
  const { page } = helpers;

  await assertNoOnboardingWizard(page);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  const depositHash = await submitAndConfirm(helpers, {
    flowName: 'deposit',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });

  // Switch tabs via the stable data attribute — plain text "Withdraw" also
  // matches an unrelated hidden quick-flow button elsewhere on the page.
  await page.locator('[data-move-flow="withdraw"]').click();
  await page.waitForTimeout(500);

  const withdrawHash = await submitAndConfirm(helpers, {
    flowName: 'withdraw',
    amountSelector: '#withdraw-amount',
    submitSelector: '#btn-withdraw',
    confirmDialogTitle: 'Confirm withdrawal',
    confirmButtonLabel: 'Withdraw',
    amount: '0.01',
    rpcUrl,
    // Generous: the just-deposited note may need the SDK's own sync-wait
    // retry (see module comment) before a withdrawal plan can build.
    progressTimeoutMs: 180000,
  });

  assert(depositHash !== withdrawHash, 'deposit and withdraw somehow produced the same transaction hash');
  console.log(
    `[04-deposit-withdraw] OK: deposit ${depositHash} and withdraw ${withdrawHash} both confirmed SUCCESS on-chain`,
  );
}

// Flagship test: full deposit happy path, submitted for real (testnet).
//
// By the time run() is called, the runner has connected Freighter. The
// profile snapshot is wizard-proof (e2e-freighter/scripts/complete-
// onboarding.mjs ran once, headed, against the working profile, and that
// state — including key derivation — was baked into the snapshot; see
// scripts/verify-onboarded.mjs), so this test goes straight to the deposit
// flow. It only asserts the wizard is absent; if it unexpectedly appears,
// that invalidates the wizard-proof-snapshot premise, so this fails loudly
// rather than trying to drive the wizard itself — report via `plan deviate`.
//
// Success proof: the deposit's own confirmed transaction, not the displayed
// pool balance. A prior version asserted a pre/post balance delta; two
// instrumented runs (see the U3c/U4 deviation history) proved the balance
// display (portfolio() via app/js/ui/dashboard.js) is eventually consistent
// against a lagging backend indexer with no client-observable freshness
// signal — the nav "Synced" indicator tracks the unrelated public-key
// registry, not pool balances. That makes any pre/post delta assertion here
// fundamentally flaky, so it's gone. The balance is still logged, purely
// informationally, since it may legitimately lag the chain for a while.
//
// waitForTransactionSuccess now lives in ../src/chain.mjs, shared with
// tests/04-deposit-withdraw.mjs.

import { waitForTransactionSuccess } from '../src/chain.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`02-deposit: ${message}`);
}

async function assertNoOnboardingWizard(page) {
  const wizardVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (wizardVisible) {
    throw new Error(
      '02-deposit: the onboarding wizard rendered on a profile that should be wizard-proof — ' +
        'this invalidates step 1.1\'s premise (a completed, re-snapshotted profile skips the wizard). ' +
        'Report via `plan deviate` rather than driving the wizard from here.',
    );
  }
}

export async function run({ page, context, waitForAnyFreighterApproval, approveOrWatch }) {
  const approve = (kind, opts) => approveOrWatch(context, kind, opts);

  await assertNoOnboardingWizard(page);

  // Informational only — see the module comment on why this can't be a
  // pre/post assertion.
  const displayedBalance = await page.locator('#move-funds-balance').innerText().catch(() => '(unavailable)');
  console.log(`[02-deposit] displayed balance before deposit (informational, may lag chain): "${displayedBalance}"`);

  const DEPOSIT_AMOUNT = '0.01';
  await page.fill('#deposit-amount', DEPOSIT_AMOUNT);

  const depositBtn = page.locator('#btn-deposit');
  await depositBtn.click();

  // The deployed app (not reflected in this checkout's app/js source — a
  // build/deploy drift found by screenshotting a live run, not by reading
  // source) raises a runtime confirmation dialog (role="dialog", title
  // "Confirm deposit") before actually submitting. It has no stable id, so
  // scope the button lookup to the dialog itself to avoid matching the
  // page's own "Deposit" button.
  const confirmDialog = page.getByRole('dialog').filter({ hasText: 'Confirm deposit' });
  const dialogAppeared = await confirmDialog
    .waitFor({ state: 'visible', timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (dialogAppeared) {
    await confirmDialog.getByRole('button', { name: 'Deposit', exact: true }).click();
  }

  // Track the button's own progress label (bindTxProgress in
  // app/js/ui/transactions.js writes the SDK's tx-progress messages there)
  // to prove the app advances through real stages, not just "did nothing".
  // The submitted transaction's full hash comes from the success toast's
  // explorer link (Utils.explorerTxUrl(hash) in app/js/ui/core.js's
  // Toast.show) — the toast's own text is truncated, but the link's href
  // carries the full hash, and multiple sequential transactions (this
  // deposit can raise more than one signTransaction approval) all resolve
  // to the SAME toast pointing at the last one.
  const seenStages = new Set();
  const progressDeadline = Date.now() + 120000;
  let txHash = null;

  while (Date.now() < progressDeadline) {
    const stageText = await depositBtn.locator('.btn-loading').innerText().catch(() => '');
    if (stageText) seenStages.add(stageText);

    // signMessage shouldn't appear here (key derivation already happened
    // during wizard completion) but is tolerated either way.
    const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
      timeoutMs: 2000,
    }).catch(() => null);
    if (pending) {
      await approve(pending.kind, { timeoutMs: 15000 });
      // A deposit can raise several sequential approvals; give the just-
      // approved popup a moment to fully close before rescanning, rather
      // than racing the next scan against its own teardown.
      await page.waitForTimeout(500);
      continue;
    }

    const toastLink = page.locator('#toast-container .toast-link:not(.hidden)').first();
    const href = await toastLink.getAttribute('href').catch(() => null);
    if (href) {
      txHash = href.split('/').filter(Boolean).pop();
      break;
    }

    const stillLoading = await depositBtn.isDisabled().catch(() => false);
    if (!stillLoading && seenStages.size > 0) {
      // Button re-enabled after showing progress, but no toast link was
      // caught (the toast auto-hides after ~4s) — one more short grace
      // window in case it's still visible right now.
      const lateHref = await toastLink.getAttribute('href').catch(() => null);
      if (lateHref) {
        txHash = lateHref.split('/').filter(Boolean).pop();
      }
      break;
    }

    await page.waitForTimeout(500);
  }

  assert(seenStages.size > 0, 'deposit button never showed a progress stage — the click may not have started anything');
  console.log(`[02-deposit] progress stages seen: ${[...seenStages].join(' -> ')}`);
  assert(txHash, 'no transaction hash was captured from the submitted-transaction toast\'s explorer link');
  console.log(`[02-deposit] captured transaction hash: ${txHash}`);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const status = await waitForTransactionSuccess(txHash, { rpcUrl });
  assert(status === 'SUCCESS', `deposit transaction ${txHash} resolved with status ${status}, not SUCCESS`);

  console.log(`[02-deposit] OK: deposit transaction ${txHash} confirmed SUCCESS on-chain`);
}

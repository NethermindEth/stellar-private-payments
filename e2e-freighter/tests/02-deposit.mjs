// Flagship test: full deposit happy path, submitted for real (testnet).
//
// By the time run() is called, the runner has connected Freighter. The
// app's onboarding wizard state is per-origin: the profile snapshot has it
// completed for the deployed app, while a fresh origin (a local build on
// localhost, CI) shows it — so this test drives it via the shared
// driveWizard helper (a no-op on an already-onboarded origin) and goes
// straight to the deposit flow.
//
// Success proof: the deposit's own confirmed transaction, not the displayed
// pool balance. A prior version asserted a pre/post balance delta; two
// instrumented runs proved the balance display (portfolio() via
// app/js/ui/dashboard.js) is eventually consistent against a lagging
// backend indexer with no client-observable freshness signal — the nav
// "Synced" indicator tracks the unrelated public-key registry, not pool
// balances. That makes any pre/post delta assertion here fundamentally
// flaky, so it's gone. The balance is still logged, purely informationally,
// since it may legitimately lag the chain for a while.
//
// waitForTransactionSuccess now lives in ../src/chain.mjs, shared with
// tests/04-deposit-withdraw.mjs.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForTransactionSuccess } from '../src/chain.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('02-deposit');

// Poll-read budget for the success toast. Must be short: the toast link is
// absent for most of the run, and every absent read costs this much.
const TOAST_READ_MS = 500;



export async function run({ page, context, waitForAnyFreighterApproval, waitForFreighterApproval, approveOrWatch }) {
  const approve = (kind, opts) => approveOrWatch(context, kind, opts);

  // The onboarding wizard's completion state is per-origin: the profile
  // snapshot carries it for the deployed app, but a fresh origin (local
  // build, CI) shows the wizard — drive it; on an onboarded origin this
  // is a no-op.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '02-deposit' });
  // A bare APP_URL (e.g. localhost) has no #move-funds hash, so the app
  // lands on Overview with the Move Funds controls hidden — switch tabs.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  // Informational only — see the module comment on why this can't be a
  // pre/post assertion.
  const displayedBalance = await page.locator('#move-funds-balance').innerText().catch(() => '(unavailable)');
  log.debug('displayed balance before deposit (informational, may lag chain):', displayedBalance);

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

  // Elapsed-time instrumentation. This loop's wall clock is dominated by work
  // that happens OUTSIDE it — the SDK's own per-transaction
  // prove -> simulate -> sign -> submit -> confirm cycle
  // (sdk/web/src/client/execute/mod.rs), whose final confirm() polls the chain
  // for up to 30s (sdk/client/src/sync.rs's confirm_tx) BEFORE the success
  // toast is ever rendered. Attributing a slow run needs per-phase timestamps,
  // not a single total: log how long each poll step actually costs, since a
  // DOM read against the app page blocks while the WASM prover holds the main
  // thread.
  const t0 = Date.now();
  const el = () => `${Date.now() - t0}ms`;
  let iteration = 0;
  log.info('deposit: submitted, entering approval/toast poll loop');

  while (Date.now() < progressDeadline) {
    iteration += 1;
    const iterStart = Date.now();

    const stageText = await depositBtn.locator('.btn-loading').innerText().catch(() => '');
    const stageReadMs = Date.now() - iterStart;
    if (stageText && !seenStages.has(stageText)) {
      seenStages.add(stageText);
      log.info(`deposit: progress stage "${stageText}" at ${el()}`);
    }
    // A DOM read that takes seconds means the app page's main thread was
    // blocked (WASM proving), not that the test was idle.
    if (stageReadMs > 1000) {
      log.info(`deposit: iteration ${iteration}: .btn-loading read blocked for ${stageReadMs}ms at ${el()}`);
    }

    // signMessage shouldn't appear here (key derivation already happened
    // during wizard completion) but is tolerated either way.
    const scanStart = Date.now();
    const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
      timeoutMs: 2000,
    }).catch(() => null);
    if (pending) {
      log.info(`deposit: approval "${pending.kind}" detected at ${el()} (scan took ${Date.now() - scanStart}ms)`);
      const approveStart = Date.now();
      await approve(pending.kind, { timeoutMs: 15000 });
      log.info(`deposit: approval "${pending.kind}" driven in ${Date.now() - approveStart}ms, now at ${el()}`);
      // A deposit can raise several sequential approvals; give the just-
      // approved popup a moment to fully close before rescanning, rather
      // than racing the next scan against its own teardown.
      await page.waitForTimeout(500);
      continue;
    }

    // Bounded read. getAttribute auto-waits for the element to exist, and the
    // toast link does not exist until the flow succeeds — so an unbounded read
    // here blocks for Playwright's 30s default on every pre-toast iteration,
    // throws, and gets swallowed by the .catch(). That stall is invisible in
    // the logs and dominates the run: it delays the rescan that drives the
    // Freighter approval, so the wallet sits open and idle the whole time.
    const toastLink = page.locator('#toast-container .toast-link:not(.hidden)').first();
    const href = await toastLink.getAttribute('href', { timeout: TOAST_READ_MS }).catch(() => null);
    if (href) {
      txHash = href.split('/').filter(Boolean).pop();
      log.info(`deposit: success toast link seen at ${el()} (iteration ${iteration})`);
      break;
    }

    const stillLoading = await depositBtn.isDisabled().catch(() => false);
    if (!stillLoading && seenStages.size > 0) {
      // Button re-enabled after showing progress, but no toast link was
      // caught (the toast auto-hides after ~4s) — one more short grace
      // window in case it's still visible right now.
      const lateHref = await toastLink.getAttribute('href', { timeout: TOAST_READ_MS }).catch(() => null);
      if (lateHref) {
        txHash = lateHref.split('/').filter(Boolean).pop();
      }
      log.info(`deposit: submit button re-enabled at ${el()}; late toast link ${lateHref ? 'found' : 'missing'}`);
      break;
    }

    await page.waitForTimeout(500);
  }

  log.info(`deposit: poll loop finished after ${iteration} iterations at ${el()}`);

  assert(seenStages.size > 0, 'deposit button never showed a progress stage — the click may not have started anything');
  log.debug('progress stages:', [...seenStages].join(' -> '));
  assert(txHash, "no transaction hash was captured from the submitted-transaction toast's explorer link");
  log.info('captured tx hash:', txHash);

  // Second confirmation of the same transaction: the SDK already polled it to
  // SUCCESS before the toast rendered, so this should cost one RPC round trip.
  // If it costs more, the toast is being rendered ahead of chain finality.
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const confirmStart = Date.now();
  const status = await waitForTransactionSuccess(txHash, { rpcUrl });
  log.info(`deposit: chain re-confirmation took ${Date.now() - confirmStart}ms, total ${el()}`);
  assert(status === 'SUCCESS', `deposit transaction ${txHash} resolved with status ${status}, not SUCCESS`);

  log.info('OK: deposit tx', txHash, 'confirmed SUCCESS on-chain');
}
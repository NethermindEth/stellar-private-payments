// Compound test: deposit 0.01 XLM, then withdraw 0.01 XLM back to the same
// (connected) wallet. submitAndConfirm (../src/moveFunds.mjs) — the runtime
// confirmation dialog, .btn-loading progress-stage tracking, sequential
// Freighter approval handling, and toast-link hash capture + on-chain
// confirmation — is shared with tests/05-deposit-transfer.mjs.
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

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`04-deposit-withdraw: ${message}`);
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;

  // Wizard state is per-origin: drive it on fresh origins, no-op elsewhere.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '04-deposit-withdraw' });
  // Bare APP_URL lands on Overview; Move Funds controls are hidden until
  // the tab is opened.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const logTag = '04-deposit-withdraw';

  const depositHash = await submitAndConfirm(helpers, {
    logTag,
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
    logTag,
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
    `[${logTag}] OK: deposit ${depositHash} and withdraw ${withdrawHash} both confirmed SUCCESS on-chain`,
  );
}

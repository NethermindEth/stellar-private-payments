// Compound test: deposit 0.01 XLM, then withdraw 0.01 XLM back to the same
// (connected) wallet. The shared move-funds operation — the runtime
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

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('04-deposit-withdraw');



export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;

  // Wizard state is per-origin: drive it on fresh origins, no-op elsewhere.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '04-deposit-withdraw' });
  await gotoMoveFunds(page);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const logTag = '04-deposit-withdraw';

  // Start the progress listener before submitting. It stays attached through
  // duplicate sync logs and proves both indexer and note-table readiness.
  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1 },
  });

  const depositResult = await deposit(helpers, {
    logTag,
    amount: '0.01',
    rpcUrl,
  });
  const depositHash = depositResult.transactionHash;

  await gotoAdvanced(page);
  const noteResult = await noteReady;
  assert(noteResult.progress.ledger > initialSync.ledger, 'indexer did not advance after the confirmed deposit');
  assert(noteResult.notes.matchingNotes.length > 0, 'no note was ready after indexer progress');

  await gotoMoveFunds(page);
  await page.getByTestId('move-flow-withdraw').click();
  await page.getByTestId('move-panel-withdraw').waitFor({ state: 'visible', timeout: 10_000 });

  const withdrawResult = await withdraw(helpers, {
    logTag,
    amount: '0.01',
    rpcUrl,
    // Generous: the just-deposited note may need the SDK's own sync-wait
    // retry (see module comment) before a withdrawal plan can build.
    progressTimeoutMs: 180000,
  });
  const withdrawHash = withdrawResult.transactionHash;

  assert(depositHash !== withdrawHash, 'deposit and withdraw somehow produced the same transaction hash');
  log.info('OK: deposit', depositHash.slice(0, 8), 'and withdraw', withdrawHash.slice(0, 8), 'both confirmed SUCCESS on-chain');
}

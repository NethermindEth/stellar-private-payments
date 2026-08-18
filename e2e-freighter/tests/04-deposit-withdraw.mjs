// Deposit 0.01 XLM, then withdraw 0.01 XLM to the connected wallet.
// The test waits for indexer progress and note readiness before withdrawal.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('04-deposit-withdraw');



export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;

  // Complete onboarding when required.
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
  await gotoMoveFlow(page, 'withdraw');

  const withdrawResult = await withdraw(helpers, {
    logTag,
    amount: '0.01',
    rpcUrl,
    // Allow the SDK to synchronize the deposited note before planning.
    progressTimeoutMs: 180000,
  });
  const withdrawHash = withdrawResult.transactionHash;

  assert(depositHash !== withdrawHash, 'deposit and withdraw somehow produced the same transaction hash');
  log.info('OK: deposit', depositHash.slice(0, 8), 'and withdraw', withdrawHash.slice(0, 8), 'both confirmed SUCCESS on-chain');
}

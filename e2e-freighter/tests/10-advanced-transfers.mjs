// Deposit, wait for the indexed note to become usable, then transfer it via
// the Advanced composer. The reusable advanced operation owns confirmation,
// Freighter approval, submitted-transaction identity, and RPC confirmation.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { advancedTransfer, deposit, waitForToast } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('10-advanced-transfers');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '10-advanced-transfers';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const recipient = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(recipient, 'E2E_ACCOUNT_D_ADDRESS is not set -- source deployments/testnet/.e2e-accounts.env first');

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1 },
  });
  const depositResult = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });

  await gotoAdvanced(page);
  const noteResult = await noteReady;
  assert(noteResult.progress.ledger > initialSync.ledger, 'indexer did not advance after the advanced-transfer deposit');
  assert(noteResult.notes.matchingNotes.length > 0, 'no deposited note was ready for the advanced composer');

  const useButton = page
    .locator('[data-testid="advanced-note"][data-note-state="available"]')
    .getByTestId('advanced-note-use')
    .first();
  await useButton.waitFor({ state: 'visible', timeout: 15_000 });
  await useButton.click();
  await waitForToast(page, {
    origin: 'advanced',
    predicate: (toast) => toast.message === 'Note added to advanced transact',
  });

  const output = page.getByTestId('advanced-output').first();
  await output.getByTestId('advanced-output-address').fill(recipient);
  const lookup = output.getByTestId('advanced-output-lookup-status');
  const resolved = await lookup
    .filter({ hasText: 'Found local registration' })
    .waitFor({ state: 'visible', timeout: 15_000 })
    .then(() => true)
    .catch(() => false);
  if (!resolved) {
    const status = await lookup.innerText().catch(() => '(unavailable)');
    assert(false, `advanced recipient registry lookup did not resolve for ${recipient} (status: "${status}")`);
  }
  await output.getByTestId('advanced-output-amount').fill('0.01');

  const advancedResult = await advancedTransfer(helpers, { logTag, rpcUrl });
  assert(
    depositResult.transactionHash !== advancedResult.transactionHash,
    'deposit and advanced transfer somehow produced the same transaction hash',
  );
  log.info('OK: 0.01 XLM advanced transfer', advancedResult.transactionHash.slice(0, 8), 'confirmed SUCCESS on-chain');
}

// Deposit then transfer to a separately provisioned, locally registered
// recipient. The transfer starts only after the indexer advanced and its
// notes table exposed the deposited note -- never after a fixed sleep.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, transfer } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { RPC_URL, createRegisteredAccount } from '../src/testAccount.mjs';

const log = createLogger('05-deposit-transfer');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '05-deposit-transfer';
  const rpcUrl = RPC_URL;

  // A passive recipient: created, funded, and registered directly through
  // the app's SDK bundle — it never needs Freighter, since it's only ever
  // looked up by address, never connected.
  const recipientAccount = await createRegisteredAccount();
  const recipient = recipientAccount.publicKey();

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
  assert(noteResult.progress.ledger > initialSync.ledger, 'indexer did not advance after the confirmed deposit');
  assert(noteResult.notes.matchingNotes.length > 0, 'no deposited note was ready after indexer progress');

  await gotoMoveFunds(page);
  await page.getByTestId('move-flow-transfer').click();
  await page.getByTestId('move-panel-transfer').waitFor({ state: 'visible', timeout: 10_000 });

  const transferResult = await transfer(helpers, {
    logTag,
    amount: '0.01',
    rpcUrl,
    fillBeforeSubmit: async () => {
      await page.locator('#transfer-address').fill(recipient);
      const registration = page.locator('#transfer-lookup-status');
      const resolved = await registration
        .filter({ hasText: 'Found local registration' })
        .waitFor({ state: 'visible', timeout: 15_000 })
        .then(() => true)
        .catch(() => false);
      if (!resolved) {
        const [status, warning] = await Promise.all([
          registration.innerText().catch(() => '(unavailable)'),
          page.locator('#transfer-lookup-warning').innerText().catch(() => '(unavailable)'),
        ]);
        assert(false, `recipient registry lookup did not resolve for ${recipient} (status: "${status}", warning: "${warning}")`);
      }
    },
  });

  assert(
    depositResult.transactionHash !== transferResult.transactionHash,
    'deposit and transfer somehow produced the same transaction hash',
  );
  log.info(
    'OK: deposit', depositResult.transactionHash.slice(0, 8),
    'and transfer', transferResult.transactionHash.slice(0, 8),
    'both confirmed SUCCESS on-chain',
  );
}

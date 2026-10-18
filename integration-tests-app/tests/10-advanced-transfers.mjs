// Deposit, wait for the indexed note to become usable, then transfer it via
// the Advanced composer. The reusable advanced operation owns confirmation,
// Freighter approval, submitted-transaction identity, and RPC confirmation.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { advancedTransfer, deposit, waitForOperationIdle, waitForToast } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { expectNoFreighterApproval } from '../src/wallet.mjs';
import { RPC_URL, createRegisteredAccount } from '../src/testAccount.mjs';

const log = createLogger('10-advanced-transfers');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '10-advanced-transfers';
  const rpcUrl = RPC_URL;

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
  // An output of the whole note leaves nothing for the pool fee, so the form
  // refuses it before any confirmation or wallet approval.
  const signer = page.getByTestId('advanced-signing-account-select');
  await signer.selectOption(await signer.locator('option').filter({ hasText: 'Deposit account' }).getAttribute('value'));
  await output.getByTestId('advanced-output-amount').fill('0.01');
  await page.locator('#btn-advanced-transact').click();
  await waitForToast(page, {
    origin: 'advanced',
    predicate: (toast) => toast.message === 'Selected notes and public deposit must add up to the private outputs, '
      + 'public withdraw and the 0.0001 XLM pool fee. Remove 0.0001 XLM from a private output.',
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened for an unbalanced advanced form');
  await expectNoFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], { timeoutMs: 5_000 });
  await waitForOperationIdle(page, { submitSelector: '#btn-advanced-transact' });

  // A balanced public deposit that leaves less than the smallest deposit is
  // refused before any confirmation, as the Deposit tab refuses it.
  const publicDeposit = page.locator('#advanced-public-deposit');
  await publicDeposit.fill('0.0005');
  await output.getByTestId('advanced-output-amount').fill('0.0104');
  await page.locator('#btn-advanced-transact').click();
  await waitForToast(page, {
    origin: 'advanced',
    predicate: (toast) => toast.message === 'Public deposit must leave at least 0.001 XLM after the 0.0001 XLM pool fee.',
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened for a public deposit below the smallest deposit');
  await expectNoFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], { timeoutMs: 5_000 });
  await waitForOperationIdle(page, { submitSelector: '#btn-advanced-transact' });
  await publicDeposit.fill('');

  // The output and the 0.0001 XLM pool fee together balance the 0.01 input note.
  await output.getByTestId('advanced-output-amount').fill('0.0099');

  const advancedResult = await advancedTransfer(helpers, { logTag, rpcUrl });
  assert(
    depositResult.transactionHash !== advancedResult.transactionHash,
    'deposit and advanced transfer somehow produced the same transaction hash',
  );
  log.info('OK: 0.0099 XLM advanced transfer', advancedResult.transactionHash.slice(0, 8), 'confirmed SUCCESS on-chain');
}

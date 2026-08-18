// Create and verify a one-note disclosure receipt for an unspent note.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { generateDisclosure, loadDisclosureReceipt, selectDisclosureNotes, verifyDisclosure } from '../src/disclosure.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit } from '../src/moveFunds.mjs';
import { gotoDisclosure, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('06-disclose-basic');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '06-disclose-basic';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const initialSync = await waitForSyncedLedger(page);
  const unspentReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1, predicate: (note) => note.state === 'available' },
  });
  const firstDeposit = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  const secondDeposit = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  assert(firstDeposit.transactionHash !== secondDeposit.transactionHash, 'the two deposits somehow produced the same transaction hash');

  await unspentReady;
  await gotoDisclosure(page);
  const receipt = await generateDisclosure(page, {
    authority: 'E2E Test Authority',
    payload: '0xdeadbeef',
    purpose: 'e2e-disclosure-basic',
    selectNotes: (target) => selectDisclosureNotes(target, { status: 'unspent' }),
  });

  await loadDisclosureReceipt(page, receipt);
  const verification = await verifyDisclosure(page);
  assert(verification.checks.proof === 'pass', 'basic disclosure proof check did not pass');
  assert(verification.checks.context === 'pass', 'basic disclosure context check did not pass');
  assert(verification.checks.root === 'pass', 'basic disclosure root check did not pass');
  assert(verification.checks.unspent === 'pass', 'basic disclosure did not report the note as unspent');
  assert(verification.noteStates.includes('unspent'), 'verified disclosure note did not have unspent state');
  await page.getByRole('status').filter({ hasText: 'Fully verified' }).waitFor({ state: 'visible', timeout: 10_000 });

  log.info('OK: one-note disclosure receipt generated and verified with proof, context, root, and unspent checks passing');
}

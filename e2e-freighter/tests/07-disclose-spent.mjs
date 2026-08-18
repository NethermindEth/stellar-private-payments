// A spent-note disclosure must retain valid proof/context/root evidence while
// reporting the spent nullifier; an unspent receipt must still fully verify.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import {
  clearDisclosureNotes,
  generateDisclosure,
  loadDisclosureReceipt,
  selectDisclosureNotes,
  verifyDisclosure,
  verifyDisclosureUntil,
} from '../src/disclosure.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoDisclosure, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('07-disclose-spent');
const PASSING_PROOF_CONTEXT_ROOT = { proof: 'pass', context: 'pass', root: 'pass' };

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '07-disclose-spent';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const deposits = [];
  for (let index = 0; index < 3; index += 1) {
    deposits.push(await deposit(helpers, { logTag, amount: '0.01', rpcUrl }));
  }
  assert(new Set(deposits.map((result) => result.transactionHash)).size === 3, 'the three deposits did not all produce distinct transaction hashes');

  const beforeWithdrawal = await waitForSyncedLedger(page);
  const spentNoteReady = waitForNotesAfterIndexer(page, {
    afterLedger: beforeWithdrawal.ledger,
    notes: { minCount: 1, predicate: (note) => note.state === 'spent' },
  });
  await gotoMoveFlow(page, 'withdraw');
  await withdraw(helpers, { logTag, amount: '0.01', rpcUrl, progressTimeoutMs: 180_000 });

  await gotoAdvanced(page);
  const spentNotes = await spentNoteReady;
  assert(spentNotes.notes.matchingNotes.length > 0, 'withdrawal completed but no spent note reached the indexed notes table');

  await gotoDisclosure(page);
  const spentReceipt = await generateDisclosure(page, {
    authority: 'E2E Test Authority',
    payload: '0xdeadbeef',
    purpose: 'e2e-disclosure-spent',
    selectNotes: (target) => selectDisclosureNotes(target, { status: 'spent' }),
  });

  await clearDisclosureNotes(page, { status: 'spent' });
  const unspentReceipt = await generateDisclosure(page, {
    authority: 'E2E Test Authority',
    payload: '0xdeadbeef',
    purpose: 'e2e-disclosure-unspent',
    selectNotes: (target) => selectDisclosureNotes(target, { status: 'unspent' }),
  });

  await loadDisclosureReceipt(page, spentReceipt);
  const spentVerification = await verifyDisclosureUntil(page, {
    checks: { ...PASSING_PROOF_CONTEXT_ROOT, unspent: 'fail' },
  });
  assert(spentVerification.noteStates.includes('spent'), 'spent disclosure receipt did not render a spent note state');
  const fullyVerifiedForSpent = await page.getByRole('status').filter({ hasText: 'Fully verified' }).isVisible().catch(() => false);
  assert(!fullyVerifiedForSpent, 'spent disclosure receipt incorrectly rendered as fully verified');

  await loadDisclosureReceipt(page, unspentReceipt);
  const unspentVerification = await verifyDisclosure(page);
  assert(unspentVerification.checks.proof === 'pass', 'unspent receipt proof check did not pass');
  assert(unspentVerification.checks.context === 'pass', 'unspent receipt context check did not pass');
  assert(unspentVerification.checks.root === 'pass', 'unspent receipt root check did not pass');
  assert(unspentVerification.checks.unspent === 'pass', 'unspent receipt was incorrectly reported as spent');
  assert(unspentVerification.noteStates.includes('unspent'), 'unspent disclosure receipt did not render an unspent note state');
  await page.getByRole('status').filter({ hasText: 'Fully verified' }).waitFor({ state: 'visible', timeout: 10_000 });

  log.info('OK: spent receipt retained proof/context/root validity with spent status; unspent receipt fully verified');
}

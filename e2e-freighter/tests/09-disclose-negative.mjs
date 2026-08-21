// Negative disclosure verification: malformed import recovery, a
// cryptographically invalid proof, and a context mismatch all stay distinct.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import {
  generateDisclosure,
  loadDisclosureReceipt,
  loadDisclosureText,
  selectDisclosureNotes,
  verifyDisclosure,
} from '../src/disclosure.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit } from '../src/moveFunds.mjs';
import { gotoDisclosure, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('09-disclose-negative');

// Flip point A's compressed y-sign flag. This keeps the point decodable yet
// changes the proof, so verification reaches the specific proof check.
function flipYSignFlag(hex) {
  const digits = '0123456789abcdef';
  const chars = hex.split('');
  const index = 64;
  chars[index] = digits[digits.indexOf(chars[index]) ^ 0x8];
  return chars.join('');
}

async function verifyWithExpectedChecks(page, receipt, expectedChecks) {
  await loadDisclosureReceipt(page, receipt);
  const verification = await verifyDisclosure(page);
  for (const [check, state] of Object.entries(expectedChecks)) {
    assert(verification.checks[check] === state, `expected disclosure ${check} check to be ${state}, got ${verification.checks[check]}`);
  }
  return verification;
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '09-disclose-negative';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);
  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1, predicate: (note) => note.state === 'available' },
  });
  await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  await noteReady;

  await gotoDisclosure(page);
  const validReceipt = await generateDisclosure(page, {
    authority: 'E2E Test Authority',
    payload: '0xdeadbeef',
    purpose: 'e2e-disclosure-negative',
    selectNotes: (target) => selectDisclosureNotes(target, { status: 'unspent' }),
  });

  // (a) The UI must report invalid JSON and accept a valid receipt directly
  // afterward without a reload.
  const garbage = await loadDisclosureText(page, '{ this is not valid json at all {{{');
  assert(garbage.state === 'error', 'garbage receipt text did not move the import UI into its error state');
  await page.getByTestId('disclosure-receipt-import-error').waitFor({ state: 'visible', timeout: 5_000 });
  const summaryVisible = await page.getByTestId('disclosure-receipt-summary').isVisible().catch(() => false);
  assert(!summaryVisible, 'garbage receipt text left the receipt summary visible');

  const recovered = await verifyWithExpectedChecks(page, validReceipt, {
    proof: 'pass', context: 'pass', root: 'pass', unspent: 'pass',
  });
  assert(recovered.noteStates.includes('unspent'), 'valid receipt did not recover to an unspent disclosure result');
  log.info('(a) malformed JSON cleanly recovered to a fully valid receipt');

  // (b) Tamper only the proof's y-sign flag: shape remains valid, but the
  // cryptographic proof check fails specifically.
  const tamperedProof = structuredClone(validReceipt);
  tamperedProof.proofCompressedHex = flipYSignFlag(validReceipt.proofCompressedHex);
  const proofResult = await verifyWithExpectedChecks(page, tamperedProof, { proof: 'fail' });
  assert(proofResult.checks.context === 'pass', 'proof-only tamper unexpectedly invalidated the context check');
  const proofFullyVerified = await page.getByRole('status').filter({ hasText: 'Fully verified' }).isVisible().catch(() => false);
  assert(!proofFullyVerified, 'tampered proof still rendered as fully verified');
  log.info('(b) proof tamper produced the specific proof failure');

  // (c) Alter the declared purpose but preserve proof bytes. The proof stays
  // valid while its committed context becomes mismatched.
  const tamperedContext = structuredClone(validReceipt);
  tamperedContext.context.purpose = `${tamperedContext.context.purpose}-tampered`;
  const contextResult = await verifyWithExpectedChecks(page, tamperedContext, { proof: 'pass', context: 'fail' });
  const contextFullyVerified = await page.getByRole('status').filter({ hasText: 'Fully verified' }).isVisible().catch(() => false);
  assert(!contextFullyVerified, 'tampered context still rendered as fully verified');
  assert(contextResult.checks.root === 'pass', 'context-only tamper unexpectedly invalidated the root check');
  log.info('(c) context tamper produced the specific context mismatch');

  log.info('OK: malformed JSON recovery, proof tamper, and context tamper all preserved distinct verification behavior');
}

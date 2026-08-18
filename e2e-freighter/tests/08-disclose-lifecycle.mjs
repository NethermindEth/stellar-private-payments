// Full receipt lifecycle: four overlapping unspent receipts and one spent
// receipt are re-verified after another withdrawal. Receipt nullifiers, not
// incidental DOM-card layout, identify exactly which receipt status changes.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import {
  clearDisclosureNotes,
  generateDisclosure,
  loadDisclosureReceipt,
  selectDisclosureNotes,
  verifyDisclosureUntil,
} from '../src/disclosure.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoDisclosure, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('08-disclose-lifecycle');
const BASE_CHECKS = { proof: 'pass', context: 'pass', root: 'pass' };
const FULLY_UNSPENT = { ...BASE_CHECKS, unspent: 'pass' };
const HAS_SPENT_NOTE = { ...BASE_CHECKS, unspent: 'fail' };

function receiptStates(receipt, verification) {
  return Object.fromEntries(receipt.publicInputs.nullifiers.map((nullifier, index) => [
    nullifier.trim().toLowerCase(),
    verification.noteStates[index],
  ]));
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '08-disclose-lifecycle';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const deposits = [];
  for (let index = 0; index < 5; index += 1) {
    deposits.push(await deposit(helpers, { logTag, amount: '0.01', rpcUrl }));
  }
  assert(new Set(deposits.map((result) => result.transactionHash)).size === 5, 'the five deposits did not all produce distinct transaction hashes');

  const beforeFirstWithdrawal = await waitForSyncedLedger(page);
  const firstSpentNoteReady = waitForNotesAfterIndexer(page, {
    afterLedger: beforeFirstWithdrawal.ledger,
    notes: { minCount: 1, predicate: (note) => note.state === 'spent' },
  });
  await gotoMoveFlow(page, 'withdraw');
  await withdraw(helpers, { logTag, amount: '0.01', rpcUrl, progressTimeoutMs: 180_000 });
  await gotoAdvanced(page);
  await firstSpentNoteReady;

  await gotoDisclosure(page);
  const receipts = {};
  for (const count of [1, 2, 3, 4]) {
    receipts[`unspent${count}`] = await generateDisclosure(page, {
      authority: 'E2E Test Authority',
      payload: '0xdeadbeef',
      purpose: `e2e-disclosure-unspent-${count}`,
      timeoutMs: 150_000,
      selectNotes: (target) => selectDisclosureNotes(target, { status: 'unspent', count }),
    });
    await clearDisclosureNotes(page, { status: 'unspent' });
  }
  receipts.spent = await generateDisclosure(page, {
    authority: 'E2E Test Authority',
    payload: '0xdeadbeef',
    purpose: 'e2e-disclosure-spent',
    timeoutMs: 150_000,
    selectNotes: (target) => selectDisclosureNotes(target, { status: 'spent' }),
  });
  await clearDisclosureNotes(page, { status: 'spent' });

  const firstPass = {};
  for (const count of [1, 2, 3, 4]) {
    const key = `unspent${count}`;
    await loadDisclosureReceipt(page, receipts[key]);
    firstPass[key] = await verifyDisclosureUntil(page, { checks: FULLY_UNSPENT, timeoutMs: 150_000 });
    assert(firstPass[key].noteStates.every((state) => state === 'unspent'), `${count}-note receipt was not fully unspent before the second withdrawal`);
  }
  await loadDisclosureReceipt(page, receipts.spent);
  firstPass.spent = await verifyDisclosureUntil(page, { checks: HAS_SPENT_NOTE, timeoutMs: 150_000 });
  assert(firstPass.spent.noteStates.includes('spent'), 'first withdrawal did not leave the spent receipt with a spent note');

  await gotoMoveFunds(page);
  const beforeSecondWithdrawal = await waitForSyncedLedger(page);
  const secondSpentNoteReady = waitForNotesAfterIndexer(page, {
    afterLedger: beforeSecondWithdrawal.ledger,
    notes: { minCount: 1, predicate: (note) => note.state === 'spent' },
  });
  await gotoMoveFlow(page, 'withdraw');
  await withdraw(helpers, { logTag, amount: '0.01', rpcUrl, progressTimeoutMs: 180_000 });
  await gotoAdvanced(page);
  await secondSpentNoteReady;
  await gotoDisclosure(page);

  // The four-note receipt covers every note that was unspent before the
  // second withdrawal, so it must reveal exactly one new spent nullifier.
  await loadDisclosureReceipt(page, receipts.unspent4);
  const afterSecondWithdrawal = await verifyDisclosureUntil(page, {
    checks: HAS_SPENT_NOTE,
    timeoutMs: 150_000,
    predicate: (verification) => verification.noteStates.filter((state) => state === 'spent').length === 1,
  });
  const fourNoteStates = receiptStates(receipts.unspent4, afterSecondWithdrawal);
  const newlySpent = Object.entries(fourNoteStates).find(([, state]) => state === 'spent');
  assert(newlySpent, 'four-note receipt did not identify a newly spent nullifier after the second withdrawal');
  const [newlySpentNullifier] = newlySpent;
  log.info('second withdrawal spent nullifier', newlySpentNullifier);

  // Every receipt is checked against its own first-pass state. Only receipts
  // containing the new nullifier may gain a spent state; no other nullifier
  // is allowed to change.
  for (const [key, receipt] of Object.entries(receipts)) {
    const previous = receiptStates(receipt, firstPass[key]);
    const expected = { ...previous };
    if (newlySpentNullifier in expected) expected[newlySpentNullifier] = 'spent';
    const expectedStates = receipt.publicInputs.nullifiers.map((nullifier) => expected[nullifier.trim().toLowerCase()]);
    const expectedChecks = expectedStates.includes('spent') ? HAS_SPENT_NOTE : FULLY_UNSPENT;

    let verification = key === 'unspent4' ? afterSecondWithdrawal : null;
    if (!verification) {
      await loadDisclosureReceipt(page, receipt);
      verification = await verifyDisclosureUntil(page, {
        checks: expectedChecks,
        timeoutMs: 150_000,
        predicate: (result) => result.noteStates.every((state, index) => state === expectedStates[index]),
      });
    }
    assert(
      verification.noteStates.every((state, index) => state === expectedStates[index]),
      `${key} receipt did not preserve the expected per-nullifier lifecycle state`,
    );
    log.info(`${key}:`, verification.noteStates.join(', '));
  }

  log.info('OK: five receipts preserve exact nullifier lifecycle state across both withdrawals');
}

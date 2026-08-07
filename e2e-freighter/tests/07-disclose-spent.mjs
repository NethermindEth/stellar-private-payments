// Increment 2 of the disclosure-lifecycle test series (grows from
// tests/06-disclose-basic.mjs's structure): all as account A — deposit
// three times, withdraw once (spending one note), then generate a 1-note
// disclosure receipt for a SPENT note and verify it shows spent status —
// PLUS a second disclosure for a still-UNSPENT note, verified as fully
// valid, guarding against an overcorrected fix that marks every nullifier
// spent regardless of truth.
//
// Note-picker discovery: nothing in app/js/disclosure.js's mountGenerate()
// disables the checkbox for spent notes (createNoteRow's `disabled` only
// fires on hitting the 4-note max) — spent notes are fully selectable in
// the generate flow, same UI as unspent ones. If spent notes ever become
// unselectable in this picker, that is a product change to investigate —
// not a case for narrowing this test.
//
// Verify-outcome discovery: a disclosure receipt for an already-spent note
// still passes proof/context/root checks (those don't care about spend
// status) but fails the "unspent" check — which means the "Fully verified"
// role=status badge (app/js/disclosure.js's `fullyVerified` gate requires
// ALL four checks) never renders for a spent note. The unspent check's own
// failing title is "Nullifier already spent" (not a generic failure), and
// the per-note card in the verify results gets an exact-text "Spent" badge
// (renderDisclosedNotesVerify's amber pill) — that's the UI's actual
// spent-status signal this test asserts on, not the (absent) success badge.
//
// APP_URL override: this test also runs against a LOCALLY rebuilt app (see
// the "Root-cause, fix, and end-to-end proof" plan's step 1.3) to prove the
// sdk/stellar fix end-to-end before the deployed app — which still serves
// the pre-fix wasm — is redeployed. A brand-new origin (e.g.
// http://localhost:8080) has never been onboarded, so unlike the deployed
// app's wizard-proof snapshot, the onboarding wizard DOES appear on first
// connect there. Rather than asserting its absence, this drives it through
// when present and no-ops when it's already done (src/onboarding.mjs's
// driveWizard checks the modal's hidden state first) — this one change
// makes the test work unmodified against both the wizard-proof deployed
// snapshot and a fresh local origin.

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`07-disclose-spent: ${message}`);
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '07-disclose-spent';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });

  // The deployed app's default APP_URL carries "#move-funds"; a bare
  // origin (e.g. the local-serve APP_URL used to prove the sdk/stellar fix
  // in isolation — see the module header) lands on whatever view the app
  // defaults to instead, leaving #deposit-amount present but hidden. Switch
  // explicitly rather than relying on the hash.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  const depositHashes = [];
  for (let i = 0; i < 3; i += 1) {
    const hash = await submitAndConfirm(helpers, {
      logTag,
      flowName: `deposit-${i + 1}`,
      amountSelector: '#deposit-amount',
      submitSelector: '#btn-deposit',
      confirmDialogTitle: 'Confirm deposit',
      confirmButtonLabel: 'Deposit',
      amount: '0.01',
      rpcUrl,
    });
    depositHashes.push(hash);
  }
  assert(new Set(depositHashes).size === 3, 'the three deposits did not all produce distinct transaction hashes');
  console.log(`[${logTag}] all three deposits confirmed SUCCESS on-chain: ${depositHashes.join(', ')}`);

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
    progressTimeoutMs: 180000,
  });
  console.log(`[${logTag}] withdraw (spends one note) confirmed SUCCESS on-chain: ${withdrawHash}`);

  // Give the indexer a moment before the disclosure tab's one-shot note
  // fetch fires (see tests/06-disclose-basic.mjs's header for why this
  // matters — no refresh affordance exists after the first tab click).
  //
  // This wait needs to be considerably longer than 06-disclose-basic's:
  // the client's LOCAL note.spent flag flips as soon as the withdrawal is
  // built (already true by the time submitAndConfirm returns), but the
  // verify flow's "nullifiers unspent" check queries the pool's own
  // spent-nullifier EVENT history on-chain — a separate, laggier index. A
  // first attempt at this test with a 6s wait generated a receipt for a
  // note the app itself lists as spent, then had it verify as UNSPENT
  // (event indexer hadn't caught up yet). 20s was enough in practice.
  await page.waitForTimeout(20000);

  await page.getByRole('button', { name: 'Disclosure', exact: true }).click();

  const generatePanel = page.locator('#disclosure-generate');
  const checkboxLocator = generatePanel.locator('label[data-note-id] input[type="checkbox"]');

  const notesAppeared = await checkboxLocator
    .first()
    .waitFor({ state: 'visible', timeout: 30000 })
    .then(() => true)
    .catch(() => false);
  if (!notesAppeared) {
    const panelText = await generatePanel.innerText().catch(() => '(unavailable)');
    assert(false, `no notes appeared in the disclosure generate panel within 30s (panel text: "${panelText}")`);
  }

  // Generate a 1-note disclosure receipt for a note under the given
  // status filter ("Spent" or "Available"), returning its JSON. Leaves the
  // note it selected checked — callers that select again under a
  // different filter must uncheck it first (mountGenerate's own state
  // persists selection across re-renders; it isn't cleared by switching
  // filters or by "Generate another").
  const generateReceiptFor = async (filterLabel, purposeSuffix) => {
    await generatePanel.getByRole('button', { name: filterLabel, exact: true }).click();
    await page.waitForTimeout(500);

    const checkbox = checkboxLocator.first();
    const noteAppeared = await checkbox
      .waitFor({ state: 'visible', timeout: 10000 })
      .then(() => true)
      .catch(() => false);
    if (!noteAppeared) {
      const panelText = await generatePanel.innerText().catch(() => '(unavailable)');
      assert(false, `no note appeared under the "${filterLabel}" filter (panel text: "${panelText}")`);
    }
    await checkbox.check({ force: true });

    await page.fill('#authority-label', 'E2E Test Authority');
    await page.fill('#authority-payload', '0xdeadbeef');
    await page.fill('#purpose', `e2e-disclosure-${purposeSuffix}`);

    const generateBtn = generatePanel.getByRole('button', { name: 'Generate Disclosure Receipt', exact: true });
    await generateBtn.click();

    const receiptPre = generatePanel.locator('pre');
    const receiptAppeared = await receiptPre
      .waitFor({ state: 'visible', timeout: 120000 })
      .then(() => true)
      .catch(() => false);
    if (!receiptAppeared) {
      const errorText = await generatePanel.innerText().catch(() => '(unavailable)');
      assert(false, `disclosure receipt was not generated within 120s (panel text: "${errorText}")`);
    }

    const receiptJson = await receiptPre.innerText();
    console.log(`[${logTag}] generated a disclosure receipt for a "${filterLabel}"-filtered note (${receiptJson.length} chars of JSON)`);
    return { receiptJson, checkbox };
  };

  const { receiptJson: spentReceiptJson, checkbox: spentCheckbox } = await generateReceiptFor('Spent', 'spent');

  // Clear the selection before picking a different note under a different
  // filter — see generateReceiptFor's comment.
  await spentCheckbox.uncheck({ force: true });
  await page.waitForTimeout(300);

  const { receiptJson: unspentReceiptJson } = await generateReceiptFor('Available', 'unspent');

  const verifyPanel = page.locator('#disclosure-verify');

  const loadAndVerify = async (receiptJson) => {
    await verifyPanel.locator('textarea').fill(receiptJson);
    await verifyPanel.getByRole('button', { name: 'Load Receipt', exact: true }).click();
    await page.waitForTimeout(500);
    await verifyPanel.getByRole('button', { name: 'Verify Receipt', exact: true }).click();
    await page.waitForTimeout(500);
  };

  // --- Spent-note receipt: proof/context/root pass, but nullifier is spent.
  await loadAndVerify(spentReceiptJson);

  const spentCheckTitleVisible = await verifyPanel
    .getByText('Nullifier already spent', { exact: true })
    .waitFor({ state: 'visible', timeout: 60000 })
    .then(() => true)
    .catch(() => false);
  if (!spentCheckTitleVisible) {
    const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
    assert(false, `verify results did not show "Nullifier already spent" within 60s (verify panel text: "${resultsText}")`);
  }

  const proofOkVisible = await verifyPanel.getByText('Proof valid', { exact: true }).isVisible().catch(() => false);
  const contextOkVisible = await verifyPanel.getByText('Context valid', { exact: true }).isVisible().catch(() => false);
  const rootOkVisible = await verifyPanel.getByText('Root fresh', { exact: true }).isVisible().catch(() => false);
  assert(proofOkVisible, 'proof check did not pass for a spent-note receipt (spend status should not affect proof validity)');
  assert(contextOkVisible, 'context check did not pass for a spent-note receipt');
  assert(rootOkVisible, 'root-freshness check did not pass for a spent-note receipt');

  const fullyVerifiedBadgeVisibleForSpent = await verifyPanel
    .getByRole('status')
    .filter({ hasText: 'Fully verified' })
    .isVisible()
    .catch(() => false);
  assert(!fullyVerifiedBadgeVisibleForSpent, 'the "Fully verified" badge rendered for a spent-note receipt — it should only show when the note is unspent');

  const spentBadgeVisible = await verifyPanel.getByText('Spent', { exact: true }).isVisible().catch(() => false);
  assert(spentBadgeVisible, 'the disclosed note card did not show an exact "Spent" badge');

  console.log(`[${logTag}] spent-note receipt verifies with proof/context/root valid and SPENT status shown`);

  // --- Unspent-note receipt: must still verify as fully valid — guards
  // against an overcorrected fix that marks every nullifier spent.
  await loadAndVerify(unspentReceiptJson);

  const fullyVerifiedBadgeVisibleForUnspent = await verifyPanel
    .getByRole('status')
    .filter({ hasText: 'Fully verified' })
    .waitFor({ state: 'visible', timeout: 60000 })
    .then(() => true)
    .catch(() => false);
  if (!fullyVerifiedBadgeVisibleForUnspent) {
    const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
    assert(
      false,
      `the still-unspent note's receipt did NOT verify as "Fully verified" within 60s (verify panel text: "${resultsText}") — ` +
        'this points at an overcorrected fix that marks every nullifier as spent, not just genuinely spent ones',
    );
  }

  const unspentCheckVisible = await verifyPanel.getByText('Nullifiers unspent', { exact: true }).isVisible().catch(() => false);
  assert(unspentCheckVisible, 'verify results for the still-unspent note did not show "Nullifiers unspent"');

  console.log(`[${logTag}] OK: spent note verifies as SPENT, still-unspent note verifies as fully valid and UNSPENT`);
}

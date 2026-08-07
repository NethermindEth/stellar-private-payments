// Full disclosure lifecycle: composes tests/06-disclose-basic.mjs and
// tests/07-disclose-spent.mjs's machinery into the user's precise scenario,
// all as account A. Deposit five times, withdraw once, generate FOUR
// disclosures covering 1, 2, 3, and 4 unspent notes respectively (all drawn
// from the same pool of notes left unspent by the first withdraw — a
// disclosure receipt proves ownership, it never consumes/spends anything,
// so the same notes can appear in more than one receipt) plus ONE
// disclosure of the note the first withdraw spent. Verify all five, then
// withdraw a second time (spending one more of the four previously-unspent
// notes) and RE-VERIFY the SAME five receipts: the receipt is a static
// artifact, but verification re-checks CURRENT chain state every time — so
// whichever receipt(s) disclose the note the second withdraw just spent
// must flip from unspent to spent, while every other receipt's result must
// stay exactly as it was. This is the core lifecycle property the whole
// "Root-cause, fix, and end-to-end proof" + "Full disclosure lifecycle"
// arc exists to prove.
//
// New discoveries beyond 06/07 (multi-note selection and re-verification):
//   - Checking a note's checkbox calls mountGenerate(container) to
//     re-render the WHOLE generate panel (app/js/disclosure.js's onToggle
//     handler) — a fresh set of DOM nodes each time, but the note list's
//     ROW ORDER is stable across re-renders (same underlying state.notes),
//     so selecting notes 0..N-1 by index across N separate check() calls
//     (each against a freshly-queried locator — Playwright locators
//     re-resolve automatically, no stale handles) reliably builds an
//     N-note selection. The same holds for unchecking to reset selection
//     before the next disclosure — mountGenerate's selection state is NOT
//     cleared by switching filters or by "Generate another" (see 07's
//     header), so this test explicitly unchecks every box it checked
//     before selecting the next set.
//   - Reading a SPECIFIC disclosed note's spent/unspent status out of a
//     multi-note verify result (to know exactly which note flipped after
//     the second withdraw) needs a per-card DOM query: each disclosed note
//     renders as a card with a stable (if unstyled-as-an-id) marker class
//     `space-y-1.5` (renderDisclosedNotesVerify's card className), inside
//     which the first `.break-all` div is the commitment and the second is
//     the FULL nullifier hex (not shortened) — and an exact-text "Spent"
//     span is present only when that specific note is spent. Cross-
//     referencing that nullifier hex against each receipt's own (locally
//     parsed, from the JSON this test already captured) `publicInputs.
//     nullifiers` array is what turns "some receipt changed" into "the
//     RIGHT receipt changed, and no others did".

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`08-disclose-lifecycle: ${message}`);
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '08-disclose-lifecycle';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });

  // See tests/07-disclose-spent.mjs's header: a bare APP_URL (local serve)
  // doesn't carry "#move-funds", so switch explicitly.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  const depositHashes = [];
  for (let i = 0; i < 5; i += 1) {
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
  assert(new Set(depositHashes).size === 5, 'the five deposits did not all produce distinct transaction hashes');
  console.log(`[${logTag}] all five deposits confirmed SUCCESS on-chain: ${depositHashes.join(', ')}`);

  const withdraw = async (flowName) => {
    // [data-move-flow="withdraw"] only exists on the Move Funds panel —
    // switch back to it first (the second withdraw runs after the first
    // verification pass, which leaves the Disclosure view active).
    await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
    await page.waitForTimeout(500);
    await page.locator('[data-move-flow="withdraw"]').click();
    await page.waitForTimeout(500);
    const hash = await submitAndConfirm(helpers, {
      logTag,
      flowName,
      amountSelector: '#withdraw-amount',
      submitSelector: '#btn-withdraw',
      confirmDialogTitle: 'Confirm withdrawal',
      confirmButtonLabel: 'Withdraw',
      amount: '0.01',
      rpcUrl,
      progressTimeoutMs: 180000,
    });
    console.log(`[${logTag}] ${flowName} confirmed SUCCESS on-chain: ${hash}`);
    return hash;
  };

  await withdraw('withdraw-1');

  // Indexer margin before the disclosure tab's one-shot note fetch and
  // before the spent-nullifier event is queryable — see 07's header.
  await page.waitForTimeout(20000);

  await page.getByRole('button', { name: 'Disclosure', exact: true }).click();

  const generatePanel = page.locator('#disclosure-generate');
  const checkboxLocator = generatePanel.locator('label[data-note-id] input[type="checkbox"]');
  const verifyPanel = page.locator('#disclosure-verify');

  const notesAppeared = await checkboxLocator
    .first()
    .waitFor({ state: 'visible', timeout: 30000 })
    .then(() => true)
    .catch(() => false);
  if (!notesAppeared) {
    const panelText = await generatePanel.innerText().catch(() => '(unavailable)');
    assert(false, `no notes appeared in the disclosure generate panel within 30s (panel text: "${panelText}")`);
  }

  // Select the first `count` notes under `filterLabel`, generate, and
  // return the receipt JSON. Leaves those `count` notes checked.
  async function generateReceiptForCount(filterLabel, count, purposeSuffix) {
    await generatePanel.getByRole('button', { name: filterLabel, exact: true }).click();
    await page.waitForTimeout(500);

    for (let i = 0; i < count; i += 1) {
      const checkbox = checkboxLocator.nth(i);
      const appeared = await checkbox
        .waitFor({ state: 'visible', timeout: 10000 })
        .then(() => true)
        .catch(() => false);
      if (!appeared) {
        const panelText = await generatePanel.innerText().catch(() => '(unavailable)');
        assert(false, `note index ${i} did not appear under the "${filterLabel}" filter (panel text: "${panelText}")`);
      }
      await checkbox.check({ force: true });
      await page.waitForTimeout(300);
    }

    await page.fill('#authority-label', 'E2E Test Authority');
    await page.fill('#authority-payload', '0xdeadbeef');
    await page.fill('#purpose', `e2e-disclosure-${purposeSuffix}`);

    const generateBtn = generatePanel.getByRole('button', { name: 'Generate Disclosure Receipt', exact: true });
    await generateBtn.click();

    const receiptPre = generatePanel.locator('pre');
    // Larger note counts prove a bigger circuit (selectiveDisclosure_N) —
    // generous margin for up to N=4.
    const receiptAppeared = await receiptPre
      .waitFor({ state: 'visible', timeout: 150000 })
      .then(() => true)
      .catch(() => false);
    if (!receiptAppeared) {
      const errorText = await generatePanel.innerText().catch(() => '(unavailable)');
      assert(false, `${count}-note disclosure receipt was not generated within 150s (panel text: "${errorText}")`);
    }

    const receiptJson = await receiptPre.innerText();
    console.log(`[${logTag}] generated a ${count}-note disclosure receipt (${purposeSuffix})`);
    return receiptJson;
  }

  // Uncheck the first `count` notes (the ones generateReceiptForCount just
  // selected) so the next call starts from a clean selection.
  async function clearSelection(count) {
    for (let i = 0; i < count; i += 1) {
      await checkboxLocator.nth(i).uncheck({ force: true });
      await page.waitForTimeout(300);
    }
  }

  const receipts = {};
  for (const count of [1, 2, 3, 4]) {
    receipts[`unspent${count}`] = await generateReceiptForCount('Available', count, `unspent-${count}`);
    await clearSelection(count);
  }
  receipts.spent = await generateReceiptForCount('Spent', 1, 'spent');
  await clearSelection(1);

  const loadAndVerify = async (receiptJson) => {
    await verifyPanel.locator('textarea').fill(receiptJson);
    await verifyPanel.getByRole('button', { name: 'Load Receipt', exact: true }).click();
    await page.waitForTimeout(500);

    const verifyBtn = verifyPanel.getByRole('button', { name: 'Verify Receipt', exact: true });
    const verifyBtnHandle = await verifyBtn.elementHandle();
    await verifyBtn.click();
    await page.waitForTimeout(300); // let the "Verifying…" disabled state actually apply first

    // Verifying re-checks proof + does a (now paginated, see the sdk/
    // stellar fix) on-chain nullifier-spent lookup — this can take well
    // over a fixed short wait, especially for a 4-note receipt. The button
    // stays disabled ("Verifying…") until the check resolves (either
    // outcome) and is the only reliable "done" signal — reading the DOM
    // before it re-enables raced ahead of the real result once and
    // silently read a stale "no verdict yet" state as "still unspent".
    const finished = await page
      .waitForFunction((btn) => !btn.disabled, verifyBtnHandle, { timeout: 150000 })
      .then(() => true)
      .catch(() => false);
    if (!finished) {
      const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
      assert(false, `verify did not finish within 150s (verify panel text: "${resultsText}")`);
    }
  };

  const isFullyVerified = async () =>
    verifyPanel
      .getByRole('status')
      .filter({ hasText: 'Fully verified' })
      .waitFor({ state: 'visible', timeout: 60000 })
      .then(() => true)
      .catch(() => false);

  const isReportedSpent = async () =>
    verifyPanel
      .getByText('Nullifier already spent', { exact: true })
      .waitFor({ state: 'visible', timeout: 60000 })
      .then(() => true)
      .catch(() => false);

  // Per-card DOM read of every disclosed note's own nullifier + spent flag
  // for whatever receipt is currently loaded — see module header.
  const readDisclosedNoteStatuses = async () => {
    const cards = verifyPanel.locator('[class*="space-y-1.5"]');
    const count = await cards.count();
    const statuses = [];
    for (let i = 0; i < count; i += 1) {
      const card = cards.nth(i);
      const spent = await card.getByText('Spent', { exact: true }).isVisible().catch(() => false);
      const nullifierHex = (await card.locator('.break-all').nth(1).innerText()).trim().toLowerCase();
      statuses.push({ nullifier: nullifierHex, spent });
    }
    return statuses;
  };

  // --- First verification pass: all four unspent-note receipts fully
  // verify; the spent-note receipt shows spent, nothing else.
  for (const count of [1, 2, 3, 4]) {
    await loadAndVerify(receipts[`unspent${count}`]);
    const ok = await isFullyVerified();
    if (!ok) {
      const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
      assert(false, `${count}-note unspent receipt did not verify as fully valid before the second withdraw (verify panel text: "${resultsText}")`);
    }
  }
  await loadAndVerify(receipts.spent);
  const spentOkFirstPass = await isReportedSpent();
  assert(spentOkFirstPass, 'the spent-note receipt did not show "Nullifier already spent" on the first verification pass');
  console.log(`[${logTag}] first verification pass: 1/2/3/4-note receipts unspent, spent-note receipt spent — as expected`);

  // --- Spend one more of the four previously-unspent notes.
  await withdraw('withdraw-2');
  await page.waitForTimeout(20000);
  await page.getByRole('button', { name: 'Disclosure', exact: true }).click();

  // The 4-note receipt covers ALL FOUR notes that were unspent going into
  // this withdrawal — whichever one withdraw-2 just spent MUST be among
  // them, so re-verifying it is how this test discovers exactly which
  // nullifier flipped, without needing to decode the withdrawal's own
  // transaction XDR.
  await loadAndVerify(receipts.unspent4);
  const statusesAfter = await readDisclosedNoteStatuses();
  assert(statusesAfter.length === 4, `expected 4 disclosed notes in the 4-note receipt's re-verify, saw ${statusesAfter.length}`);
  const newlySpent = statusesAfter.filter((s) => s.spent);
  assert(
    newlySpent.length === 1,
    `expected exactly 1 newly-spent nullifier in the 4-note receipt after the second withdraw, saw ${newlySpent.length} ` +
      '— more than one suggests the second withdraw spent more than one note (unexpected for an exact 0.01 match), ' +
      'and zero would mean re-verification did not reflect the new spend at all (a verification-layer finding — investigate, do not weaken this assertion)',
  );
  const newlySpentNullifier = newlySpent[0].nullifier;
  console.log(`[${logTag}] withdraw-2 spent nullifier ${newlySpentNullifier} (discovered via the 4-note receipt's re-verify)`);

  // --- Re-verify every other receipt against its OWN previous status
  // (`previousStatus`: what the first verification pass found — 'unspent'
  // for the four unspent-note receipts, 'spent' for the one already spent
  // by withdraw-1): CHANGED to spent if it discloses the just-spent
  // nullifier, UNCHANGED (same as before) otherwise. "Unchanged" means
  // different things depending on where it started — still fully verified
  // for a previously-unspent receipt, still reported spent for the one
  // already spent by withdraw-1 (whose own nullifier is necessarily a
  // DIFFERENT note than whatever withdraw-2 just spent, since withdraw-2
  // only had unspent notes to draw from).
  const checkReceipt = async (label, receiptJson, previousStatus) => {
    const parsed = JSON.parse(receiptJson);
    const nullifiers = parsed.publicInputs.nullifiers.map((n) => n.trim().toLowerCase());
    const discloses = nullifiers.includes(newlySpentNullifier);

    await loadAndVerify(receiptJson);
    const spentNow = await isReportedSpent();

    if (discloses) {
      assert(
        spentNow,
        `${label}: discloses the newly-spent nullifier but did NOT show "Nullifier already spent" on re-verify — re-verification did not reflect the new spend`,
      );
      assert(
        previousStatus === 'unspent',
        `${label}: test bookkeeping error — a receipt already known spent shouldn't newly disclose a different freshly-spent nullifier as itself`,
      );
      console.log(`[${logTag}] ${label}: CHANGED unspent -> spent, as expected (discloses the just-spent nullifier)`);
    } else if (previousStatus === 'unspent') {
      assert(!spentNow, `${label}: does not disclose the newly-spent nullifier but showed "Nullifier already spent" anyway — an incorrect/overcorrected spent check`);
      const stillFullyVerified = await isFullyVerified();
      assert(stillFullyVerified, `${label}: expected to remain fully verified/unspent (unrelated to the second withdraw) but did not`);
      console.log(`[${logTag}] ${label}: UNCHANGED (still unspent), as expected`);
    } else {
      assert(spentNow, `${label}: was already spent (from the first withdraw) but no longer shows "Nullifier already spent" on re-verify`);
      console.log(`[${logTag}] ${label}: UNCHANGED (still spent from withdraw-1), as expected`);
    }
  };

  await checkReceipt('1-note receipt', receipts.unspent1, 'unspent');
  await checkReceipt('2-note receipt', receipts.unspent2, 'unspent');
  await checkReceipt('3-note receipt', receipts.unspent3, 'unspent');
  // unspent4 already re-verified above to discover newlySpentNullifier;
  // it necessarily discloses it (that's how it was found), so it's the
  // one receipt guaranteed to have changed.
  await checkReceipt('spent-note receipt', receipts.spent, 'spent');

  console.log(`[${logTag}] OK: re-verification reflects current chain state — only the receipt(s) disclosing the just-spent note changed`);
}

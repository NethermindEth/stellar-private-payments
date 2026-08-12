// Increment 1 of the disclosure-lifecycle test series: the smallest
// end-to-end path, entirely as account A — deposit twice, generate a
// 1-note selective-disclosure receipt for an unspent note, then verify
// that SAME receipt through the app's own (walletless-capable, but here
// wallet-backed) verify flow. No second account, no account switching:
// switching Freighter's active account to one never granted
// access to the app's origin leaves the app silently showing the PREVIOUS
// account's session with no detectable signal, which blocks any
// multi-account scenario until that's resolved. This increment proves the
// create→capture→verify path in isolation first; later increments grow
// spent-note and cross-account semantics from this template.
//
// Disclosure tab UI discovery (app/js/disclosure.js — this checkout's
// source DOES match the deployed app here, unlike the Move Funds runtime-
// dialog drift 02/04/05 found):
//   - Tab switch: the top-nav button named exactly "Disclosure" — NOT the
//     `[data-view="disclosure"]` selector alone, which also matches every
//     note row's own per-row "Disclose" quick button in the Advanced
//     table (app/index.html:650). The panel only
//     ever mounts and fetches notes ONCE per page load (navigation.js's
//     `disclosureLoaded` flag) — there is no refresh affordance, so the
//     note fetch that follows the FIRST click is the only chance to see
//     freshly deposited notes; a generous wait before that first click
//     gives the indexer room to catch up (the same eventually-consistent
//     lag 02-deposit.mjs documents for the balance display, here mattering
//     for note visibility instead).
//   - Generate panel: `#disclosure-generate`. Status filter buttons
//     ("All"/"Available"/"Spent") are plain <button> elements with no
//     id/testid, but "Available" ALSO appears as a <span> status badge on
//     every unspent note row — the badge is not a button, so scoping the
//     lookup to `getByRole('button', ...)` disambiguates them cleanly.
//   - Each note row is a `<label data-note-id="...">` wrapping a checkbox
//     input (app/js/ui/notes-view.js's createNoteRow) — select the first
//     one under the "Available" filter; this test doesn't need it to be
//     one of the two notes just deposited, only unspent (deposit twice
//     purely to guarantee at least one exists even if older test runs left
//     the account with none).
//   - The generate form's context-nonce field is pre-filled with a random
//     valid nonce; only authority-label/authority-payload/purpose need
//     filling. The submit button's accessible name ("Generate Disclosure
//     Receipt") collides with the panel's own `<h2>` heading text, so it
//     must be matched via `getByRole('button', ...)`, not `getByText`.
//   - On success the receipt JSON is rendered verbatim in a `<pre>` inside
//     `#disclosure-generate` — reading that directly is simpler than
//     driving the "Copy to clipboard" button through clipboard
//     permissions.
//   - Verify panel: `#disclosure-verify`. Paste the receipt JSON into its
//     `<textarea>`, click "Load Receipt", then "Verify Receipt" (both
//     button names are unique within this panel). A fully-passing
//     verification renders a `role="status"` badge reading "Fully
//     verified — this receipt is trustworthy."; the per-check list itself
//     is what actually assigns the note's unspent/spent read — the passing
//     text for that check is literally "Nullifiers unspent".

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';

const log = createLogger('06-disclose-basic');


export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '06-disclose-basic';

  // Wizard state is per-origin: drive it on fresh origins, no-op elsewhere.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  // Bare APP_URL lands on Overview; Move Funds controls are hidden until
  // the tab is opened.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  const depositHash1 = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'deposit-1',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });

  const depositHash2 = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'deposit-2',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });

  assert(depositHash1 !== depositHash2, 'the two deposits somehow produced the same transaction hash');
  log.info(`both deposits confirmed SUCCESS on-chain: ${depositHash1}, ${depositHash2}`);

  // Give the indexer a moment before the disclosure tab's one-shot note
  // fetch fires (see module header) — this is the only chance to see them.
  await page.waitForTimeout(6000);

  // `[data-view="disclosure"]` is not unique: every note row in the
  // Advanced table also carries it on its own per-row "Disclose" quick
  // button (app/index.html:650). The top-nav tab is the only one that's
  // also a role=button named exactly "Disclosure".
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
    assert(
      false,
      `no notes appeared in the disclosure generate panel within 30s after two confirmed deposits ` +
        `(panel text: "${panelText}") — likely indexer lag past this test's wait margin, not a UI bug; ` +
        'consider raising the wait if this recurs',
    );
  }

  // Filter to unspent notes so the first checkbox is guaranteed unspent —
  // "Available" also appears as a per-row status badge (a <span>, not a
  // button), so scoping to role=button disambiguates.
  await generatePanel.getByRole('button', { name: 'Available', exact: true }).click();
  await page.waitForTimeout(500);

  const availableCheckbox = checkboxLocator.first();
  await availableCheckbox.waitFor({ state: 'visible', timeout: 10000 });
  await availableCheckbox.check({ force: true });

  await page.fill('#authority-label', 'E2E Test Authority');
  await page.fill('#authority-payload', '0xdeadbeef');
  await page.fill('#purpose', 'e2e-disclosure-basic');
  // #context-nonce is pre-filled with a valid random nonce by the app itself.

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
  log.info(`generated a disclosure receipt (${receiptJson.length} chars of JSON)`);

  const verifyPanel = page.locator('#disclosure-verify');
  await verifyPanel.locator('textarea').fill(receiptJson);
  await verifyPanel.getByRole('button', { name: 'Load Receipt', exact: true }).click();
  await page.waitForTimeout(500);

  await verifyPanel.getByRole('button', { name: 'Verify Receipt', exact: true }).click();

  const fullyVerifiedBadge = verifyPanel.getByRole('status').filter({ hasText: 'Fully verified' });
  const verifiedOk = await fullyVerifiedBadge
    .waitFor({ state: 'visible', timeout: 60000 })
    .then(() => true)
    .catch(() => false);
  if (!verifiedOk) {
    const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
    assert(false, `receipt did not verify as fully valid within 60s (verify panel text: "${resultsText}")`);
  }

  const unspentCheckVisible = await verifyPanel.getByText('Nullifiers unspent', { exact: true }).isVisible().catch(() => false);
  assert(unspentCheckVisible, 'verify results did not show "Nullifiers unspent" — the disclosed note\'s status is not UNSPENT');

  log.info(`OK: 1-note disclosure receipt created and verified as VALID with UNSPENT status`);
}

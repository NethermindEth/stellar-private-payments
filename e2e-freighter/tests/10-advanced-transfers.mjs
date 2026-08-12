// Advanced-view transfer: the last item on the user's original test-plan
// list. Nothing has exercised the Advanced tab before this — it's a
// distinct UI surface from Move Funds, discovered here (not assumed) by
// reading app/js/ui/transactions.js and app/js/ui/templates.js/notes-
// table.js directly, since no prior test's header covers it.
//
// Advanced UI discovery (app/index.html's `data-view-panel="advanced"`,
// app/js/ui/transactions.js, app/js/ui/notes-table.js):
//   - Tab switch: the top-nav button named exactly "Advanced" (same pattern
//     as "Move Funds"/"Disclosure" in 07/08/09 — role=button, exact text).
//   - The panel is a fixed-shape composer around the SDK's single-step
//     `transact` call (sdk/web/src/client/transact.rs's TransactConfig),
//     NOT a form with recipient/amount fields, NOT a JSON textarea, and
//     NOT a multi-step plan builder — there is exactly one "Execute
//     Advanced Transaction" button (`#btn-advanced-transact`) that builds
//     ONE `Transact` step from whatever is currently in the composer:
//       - Up to 2 spendable input notes: `#advanced-inputs .note-input`
//         (2 rows, built once by buildAdvancedComposer()). Left blank, or
//         filled by clicking a note's own "Use" button in the notes table
//         (`#advanced-notes-tbody .note-use`) — that dispatches
//         `advanced:use-note`, which fills the first EMPTY `.note-input`
//         and shows a "Note added to advanced transact" toast. A spent
//         note's own Use button is hidden entirely (can't be selected).
//       - Up to 2 outputs: `#advanced-outputs .advanced-output-row` (2
//         rows), each with `.output-address` (triggers the SAME registry-
//         lookup-on-56-chars pattern 05/07 already document — success
//         fills `.lookup-status` with "Found local registration"; failure
//         reveals `.manual-fields` for a manual note/encryption key) and
//         `.output-amount`.
//       - `#advanced-public-deposit` / `#advanced-public-withdraw`: public
//         (non-private) amounts in/out — a pure private-to-private
//         transfer (this test's scenario) leaves both at their default
//         empty value, which parses as 0.
//       - `#advanced-public-recipient` auto-fills with the connected
//         wallet address on `wallet:ready`; it only matters when the
//         public ext-amount nets negative (a public withdraw target), so a
//         pure private transfer never touches it.
//   - The notes table (unlike Disclosure's one-shot-per-page-load fetch)
//     polls every 8s once connected (NotesTable.startPolling(), started on
//     'wallet:ready', independent of which tab is active) — no special
//     "first click" timing concern here, just the usual indexer-lag margin
//     before a freshly-deposited note shows up as usable.
//   - Advanced DOES route through the shared confirmation modal in this
//     checkout, exactly like the Move Funds flows: app/js/ui/transactions.js
//     awaits confirmAction({ title: 'Confirm advanced transaction',
//     confirmLabel: 'Transact' }) and returns early unless it resolves true,
//     so nothing is planned, signed, or submitted until it is confirmed.
//     Note the button reads "Transact", NOT "Transaction" — a name regex
//     built around the dialog's title rather than its button label matches
//     nothing and hangs here.
//   - Progress/result: identical mechanism to Move Funds — `.btn-loading`
//     text on the submit button tracks live progress-stage messages, and
//     on success a toast (`#toast-container .toast-link`) carries the full
//     transaction hash in its href, truncated in its visible text. Exactly
//     one hash for a single-step transact.
//
// Follow-up candidates (deliberately NOT built here, per this step's scope
// limit): a multi-input/multi-output single transact (2 notes in, 2
// outputs), and a combined public-deposit-plus-private-output transact.

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { waitForTransactionSuccess } from '../src/chain.mjs';

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';

const log = createLogger('10-advanced-transfers');
export async function run(helpers) {
  const { page, context, waitForAnyFreighterApproval, approveOrWatch, waitForFreighterApproval } = helpers;
  const logTag = '10-advanced-transfers';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const recipient = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(recipient, 'E2E_ACCOUNT_D_ADDRESS is not set — source deployments/testnet/.e2e-accounts.env first');

  const depositHash = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'deposit',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });
  log.info(`deposit confirmed SUCCESS on-chain: ${depositHash}`);

  // Give the notes-table poll (every 8s, already running since connect —
  // see module header) and indexer time to surface the new note.
  await page.waitForTimeout(20000);

  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await page.waitForTimeout(500);

  const useBtn = page.locator('#advanced-notes-tbody .note-use').first();
  const noteAppeared = await useBtn
    .waitFor({ state: 'visible', timeout: 30000 })
    .then(() => true)
    .catch(() => false);
  if (!noteAppeared) {
    const tbodyText = await page.locator('#advanced-notes-tbody').innerText().catch(() => '(unavailable)');
    assert(false, `no usable note appeared in the Advanced notes table within 30s (table text: "${tbodyText}")`);
  }
  await useBtn.click();

  const useToastVisible = await page
    .getByText('Note added to advanced transact', { exact: true })
    .waitFor({ state: 'visible', timeout: 10000 })
    .then(() => true)
    .catch(() => false);
  assert(useToastVisible, '"Note added to advanced transact" toast did not appear after clicking Use');

  const firstOutputRow = page.locator('#advanced-outputs .advanced-output-row').first();
  await firstOutputRow.locator('.output-address').fill(recipient);

  const lookupOk = await firstOutputRow
    .locator('.lookup-status')
    .filter({ hasText: 'Found local registration' })
    .waitFor({ state: 'visible', timeout: 15000 })
    .then(() => true)
    .catch(() => false);
  if (!lookupOk) {
    const status = await firstOutputRow.locator('.lookup-status').innerText().catch(() => '(unavailable)');
    const warning = await firstOutputRow.locator('.lookup-warning').innerText().catch(() => '(unavailable)');
    assert(
      false,
      `recipient registry lookup did not resolve to "Found local registration" within 15s ` +
        `(status: "${status}", warning: "${warning}") — this points at a registration problem with ${recipient}, ` +
        'not a timing issue',
    );
  }
  await firstOutputRow.locator('.output-amount').fill('0.01');

  const previousHref = await page
    .locator('#toast-container .toast-link:not(.hidden)')
    .first()
    .getAttribute('href')
    .catch(() => null);

  const submitBtn = page.locator('#btn-advanced-transact');
  await submitBtn.click();

  // Confirm the modal, per the module header. Required, not defensive:
  // transactions.js returns early unless confirmAction resolves true, so
  // without this click nothing is ever planned or submitted and the wait
  // for a progress stage below times out with no toast to explain it.
  const confirmDialog = page.getByRole('dialog').filter({ hasText: 'Confirm advanced transaction' });
  await confirmDialog.waitFor({ state: 'visible', timeout: 10000 });
  await confirmDialog.getByRole('button', { name: 'Transact', exact: true }).click();
  log.info('confirmed the "Confirm advanced transaction" dialog');

  const seenStages = new Set();
  const progressDeadline = Date.now() + 180000;
  let txHash = null;
  const toastLink = page.locator('#toast-container .toast-link:not(.hidden)').first();

  while (Date.now() < progressDeadline) {
    const stageText = await submitBtn.locator('.btn-loading').innerText().catch(() => '');
    if (stageText) seenStages.add(stageText);

    const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
      timeoutMs: 2000,
    }).catch(() => null);
    if (pending) {
      await approveOrWatch(context, pending.kind, { timeoutMs: 15000 });
      await page.waitForTimeout(500);
      continue;
    }

    const href = await toastLink.getAttribute('href').catch(() => null);
    if (href && href !== previousHref) {
      txHash = href.split('/').filter(Boolean).pop();
      break;
    }

    const stillLoading = await submitBtn.isDisabled().catch(() => false);
    if (!stillLoading && seenStages.size > 0) {
      const lateHref = await toastLink.getAttribute('href').catch(() => null);
      if (lateHref && lateHref !== previousHref) txHash = lateHref.split('/').filter(Boolean).pop();
      break;
    }

    await page.waitForTimeout(500);
  }

  assert(seenStages.size > 0, 'the Execute Advanced Transaction button never showed a progress stage — the click may not have started anything');
  log.debug(`advanced transact progress stages seen: ${[...seenStages].join(' -> ')}`);
  assert(txHash, 'no transaction hash was captured from the submitted-transaction toast\'s explorer link');
  log.info(`advanced transact captured transaction hash: ${txHash}`);

  assert(depositHash !== txHash, 'deposit and advanced-transfer somehow produced the same transaction hash');

  const status = await waitForTransactionSuccess(txHash, { rpcUrl, timeoutMs: 60000 });
  assert(status === 'SUCCESS', `advanced transfer transaction ${txHash} resolved with status ${status}, not SUCCESS`);

  log.info(`OK: 0.01 XLM transfer via the Advanced view (${txHash}) confirmed SUCCESS on-chain`);
}

// Failure-mode battery for the money flows, all as account A against the
// locally built app (self-orchestrated trunk serve, per 07-10's pattern).
// Composes 05-deposit-transfer.mjs's recipient-lookup pattern and src/
// moveFunds.mjs's submitAndConfirm; see those for the machinery this
// builds on.
//
// Where each failure is actually enforced (discovered by reading the SDK
// and contract source, not assumed):
//   - OVER-WITHDRAW / OVER-TRANSFER: tx-planner's coin selection
//     (sdk/tx-planner/src/plan/error.rs's `PlanError::NoCombination`,
//     Display text "no combination of notes reaches the goal amount") runs
//     entirely LOCALLY against the wallet's already-synced notes — no RPC
//     round-trip, no simulation, no signing. sdk/client/src/error.rs's
//     `Error::Plan(#[from] PlanError)` is `#[error(transparent)]`, so that
//     exact Display text reaches the JS catch block unchanged. app/js/ui/
//     errors.js's CONTRACT_ERRORS/ERROR_PATTERNS tables have no entry
//     matching this text, so it falls through to the generic fallback:
//     `"${operationType} failed: ${rawMessage}"` — i.e. the toast reads
//     "Withdraw failed: no combination of notes reaches the goal amount"
//     or "Transfer failed: ...". Fast and deterministic: no Freighter
//     approval ever appears.
//   - UNREGISTERED RECIPIENT: app/js/ui/transactions.js's
//     `lookupRecipient()` — the SAME local-registry lookup 05 already
//     documents — sets `#transfer-lookup-status` to "No local registration
//     found" for any address with no registry entry, purely from the
//     `client().recipientLookup()` call's `{ entry: null }` result. No
//     amount, no submission, no signing needed to observe this — it fires
//     on the `input` listener the moment a 56-char address is typed.
//   - ABOVE MAX-DEPOSIT: NOT a client-side check anywhere in the SDK
//     (grepped sdk/client and sdk/tx-planner — no maximum_deposit_amount
//     reference at all outside sdk/stellar's state-fetching code, which
//     the deposit flow doesn't even consult). The cap is enforced ONLY
//     inside the pool contract's own `transact()` invocation
//     (contracts/pool/src/pool.rs: `if deposit_u > max { return
//     Err(Error::WrongExtAmount) }`, error code 6) — meaning it only
//     surfaces via Soroban's `simulateTransaction` (which actually
//     executes the contract to compute fees/footprint) BEFORE signing,
//     not via any pre-flight client validation. This does NOT fall
//     through to the generic per-operation fallback text (a first attempt
//     at this test assumed it would, and was wrong): app/js/ui/errors.js's
//     ERROR_PATTERNS list is checked before the generic fallback, and its
//     "simulation"+"fail" pattern matches first, so the toast reads the
//     fixed, specific text "Transaction simulation failed. The contract
//     rejected the transaction." — not "Deposit failed: ...". Confirmed by
//     instrumenting a live run and watching the button/toast state
//     directly (~4-5s after clicking Deposit: button reverts from
//     "Proving…" to idle, that exact toast appears).
//   Confirmed live via the deployed pool's own on-chain state (not
//   trusted from the user's stated figure): `MaximumDepositAmount` =
//   1,000,000,000 stroops = exactly 100 XLM, fetched directly via
//   `getLedgerEntries` against the DataKey (a soroban-sdk enum unit
//   variant serializes as `ScVal::Vec([Symbol(variant_name)])`, not a bare
//   Symbol — the same "read the else branch" lesson from the nullifier-
//   topic-filter fix applies here too). This account's friendbot balance
//   is orders of magnitude above 100 XLM, so a deposit-side
//   INSUFFICIENT-FUNDS case is unreachable and isn't attempted here.
//
// Toast lifecycle note: error toasts (Toast.show(msg, 'error')) share the
// same template as success toasts and auto-remove from the DOM ~4.2s after
// appearing (core.js's Toast.show: 4000ms + 200ms fade) — polling must
// start immediately after the triggering click, not after some other wait.

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`11-failure-modes: ${message}`);
}

export async function run(helpers) {
  const { page, context, waitForAnyFreighterApproval, approveOrWatch, waitForFreighterApproval } = helpers;
  const logTag = '11-failure-modes';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const recipient = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(recipient, 'E2E_ACCOUNT_D_ADDRESS is not set — source deployments/testnet/.e2e-accounts.env first');

  const baselineDepositHash = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'baseline-deposit',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });
  console.log(`[${logTag}] baseline 0.01 XLM deposit confirmed SUCCESS on-chain: ${baselineDepositHash}`);
  await page.waitForTimeout(20000); // let the note become locally spendable, per 07's discovery

  // This is the SAME persistent Freighter/wallet profile every prior test
  // in this whole session has deposited into — by this point it holds a
  // real, accumulated unspent balance well above any single "10x the
  // baseline deposit" guess (discovered empirically: a hardcoded 0.1 XLM
  // over-withdraw here first ran to a successful multi-note "Proving step
  // 1/9…" instead of failing, because the account already held ~0.8 XLM
  // from unrelated earlier tests). Read the actual displayed balance and
  // pick an amount confidently above it instead of guessing.
  const displayedBalanceText = await page.locator('#move-funds-balance').innerText().catch(() => '0');
  const currentBalance = parseFloat(displayedBalanceText) || 0;
  const overAmount = String(currentBalance * 10 + 10);
  console.log(`[${logTag}] current displayed balance: "${displayedBalanceText}" — using ${overAmount} XLM for the over-withdraw/over-transfer cases`);

  // Generate a valid, never-registered Stellar address for case 3 — a
  // real ed25519 keypair via the same esm.sh dynamic-import trick already
  // proven in this session, not a hand-rolled string (which the UI's own
  // 56-char length check would accept, but client().recipientLookup()
  // might reject outright as malformed rather than cleanly returning "not
  // found" — a different, undesired failure mode).
  const unregisteredAddress = await page.evaluate(async () => {
    const mod = await import('https://esm.sh/@stellar/stellar-sdk@13');
    const sdk = mod.default;
    return sdk.Keypair.random().publicKey();
  });
  console.log(`[${logTag}] generated a never-registered address for case 3: ${unregisteredAddress}`);

  // Read the most recent toast message's text, polling briefly. Toasts
  // auto-remove ~4.2s after appearing (see module header) — this must be
  // called immediately after the triggering action, and itself polls
  // frequently so it doesn't miss a toast that appears and fades within
  // its own wait window.
  const waitForToastText = async (predicate, timeoutMs = 8000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const messages = await page.locator('#toast-container .toast-message').allInnerTexts().catch(() => []);
      const match = messages.find(predicate);
      if (match) return match;
      await page.waitForTimeout(250);
    }
    return null;
  };

  const noApprovalAppeared = async (timeoutMs = 5000) =>
    waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], { timeoutMs })
      .then(() => false)
      .catch(() => true);

  const currentToastLinkHref = () =>
    page.locator('#toast-container .toast-link:not(.hidden)').first().getAttribute('href').catch(() => null);

  // --- (1) OVER-WITHDRAW: 10x the deposit, no combination of notes covers it.
  await page.locator('[data-move-flow="withdraw"]').click();
  await page.waitForTimeout(500);
  const hrefBeforeOverWithdraw = await currentToastLinkHref();
  await page.fill('#withdraw-amount', overAmount);
  await page.locator('#btn-withdraw').click();

  const overWithdrawToast = await waitForToastText((t) => /no combination of notes/i.test(t));
  if (!overWithdrawToast) {
    const allToasts = await page.locator('#toast-container .toast-message').allInnerTexts().catch(() => []);
    assert(false, `over-withdraw did not surface the specific "no combination of notes" failure (toasts seen: ${JSON.stringify(allToasts)})`);
  }
  assert(/^withdraw failed/i.test(overWithdrawToast), `over-withdraw toast was not prefixed "Withdraw failed": "${overWithdrawToast}"`);
  console.log(`[${logTag}] (1) over-withdraw: "${overWithdrawToast}"`);

  const noApprovalForOverWithdraw = await noApprovalAppeared();
  assert(noApprovalForOverWithdraw, 'over-withdraw raised a Freighter approval prompt — it should fail before any signing');
  const hrefAfterOverWithdraw = await currentToastLinkHref();
  assert(hrefAfterOverWithdraw === hrefBeforeOverWithdraw, 'over-withdraw produced a new submitted-transaction toast link — something was submitted');

  const withdrawBtnIdle = await page.locator('#btn-withdraw').isEnabled().catch(() => false);
  assert(withdrawBtnIdle, 'the Withdraw button is not back to an idle (enabled) state after the over-withdraw failure');
  await page.fill('#withdraw-amount', '');

  // --- (2) OVER-TRANSFER: same mechanism, through the transfer UI, to a
  // REGISTERED recipient (recipient resolution is not the failure here).
  await page.locator('[data-move-flow="transfer"]').click();
  await page.waitForTimeout(500);
  await page.fill('#transfer-address', recipient);
  const lookupOk = await page
    .locator('#transfer-lookup-status')
    .filter({ hasText: 'Found local registration' })
    .waitFor({ state: 'visible', timeout: 15000 })
    .then(() => true)
    .catch(() => false);
  assert(lookupOk, `recipient ${recipient} did not resolve via local registration — case 2 needs a registered recipient to isolate the balance failure`);

  const hrefBeforeOverTransfer = await currentToastLinkHref();
  await page.fill('#transfer-amount', overAmount);
  await page.locator('#btn-transfer').click();

  const overTransferToast = await waitForToastText((t) => /no combination of notes/i.test(t));
  assert(overTransferToast, 'over-transfer did not surface the specific "no combination of notes" failure');
  assert(/^transfer failed/i.test(overTransferToast), `over-transfer toast was not prefixed "Transfer failed": "${overTransferToast}"`);
  console.log(`[${logTag}] (2) over-transfer: "${overTransferToast}"`);

  const noApprovalForOverTransfer = await noApprovalAppeared();
  assert(noApprovalForOverTransfer, 'over-transfer raised a Freighter approval prompt — it should fail before any signing');
  const hrefAfterOverTransfer = await currentToastLinkHref();
  assert(hrefAfterOverTransfer === hrefBeforeOverTransfer, 'over-transfer produced a new submitted-transaction toast link — something was submitted');

  const transferBtnIdle = await page.locator('#btn-transfer').isEnabled().catch(() => false);
  assert(transferBtnIdle, 'the Transfer button is not back to an idle (enabled) state after the over-transfer failure');
  await page.fill('#transfer-amount', '');
  await page.fill('#transfer-address', '');
  await page.waitForTimeout(500); // let the address-cleared lookup reset settle

  // --- (3) UNREGISTERED RECIPIENT: distinct lookup failure, before any
  // amount/signing even comes into play.
  await page.fill('#transfer-address', unregisteredAddress);
  const notFoundVisible = await page
    .locator('#transfer-lookup-status')
    .filter({ hasText: 'No local registration found' })
    .waitFor({ state: 'visible', timeout: 15000 })
    .then(() => true)
    .catch(() => false);
  if (!notFoundVisible) {
    const status = await page.locator('#transfer-lookup-status').innerText().catch(() => '(unavailable)');
    const warning = await page.locator('#transfer-lookup-warning').innerText().catch(() => '(unavailable)');
    assert(
      false,
      `unregistered recipient did not show "No local registration found" within 15s ` +
        `(status: "${status}", warning: "${warning}")`,
    );
  }
  const manualFieldsRevealed = await page.locator('#transfer-manual-fields').isVisible().catch(() => false);
  assert(manualFieldsRevealed, 'manual key-entry fields did not reveal for an unregistered recipient');
  console.log(`[${logTag}] (3) unregistered recipient: "No local registration found" shown, manual fields revealed, no signing prompt reached`);
  await page.fill('#transfer-address', '');

  // --- (4) ABOVE MAX-DEPOSIT: 150 XLM against a 100 XLM on-chain cap
  // (confirmed live — see module header), enforced only inside the
  // contract's transact() call, surfacing via simulateTransaction.
  await page.locator('[data-move-flow="deposit"]').click();
  await page.waitForTimeout(500);
  const hrefBeforeOverCap = await currentToastLinkHref();
  await page.fill('#deposit-amount', '150');
  await page.locator('#btn-deposit').click();

  const overCapToast = await waitForToastText((t) => /simulation failed/i.test(t), 20000);
  if (!overCapToast) {
    const allToasts = await page.locator('#toast-container .toast-message').allInnerTexts().catch(() => []);
    assert(
      false,
      `a deposit of 150 XLM (above the 100 XLM on-chain cap) did not produce a "Transaction simulation failed" toast within 20s ` +
        `(toasts seen: ${JSON.stringify(allToasts)}) — a silent success above the cap is a product finding, ` +
        'report via `plan deviate`, do not assert around it',
    );
  }
  console.log(`[${logTag}] (4) above max-deposit: "${overCapToast}"`);

  const noApprovalForOverCap = await noApprovalAppeared();
  assert(noApprovalForOverCap, 'a deposit above the max-deposit cap raised a Freighter approval prompt — it should fail during simulation, before signing');
  const hrefAfterOverCap = await currentToastLinkHref();
  assert(hrefAfterOverCap === hrefBeforeOverCap, 'a deposit above the max-deposit cap produced a new submitted-transaction toast link — something was submitted');

  const depositBtnIdle = await page.locator('#btn-deposit').isEnabled().catch(() => false);
  assert(depositBtnIdle, 'the Deposit button is not back to an idle (enabled) state after the above-max-deposit failure');
  await page.fill('#deposit-amount', '');

  // --- Recovery proof: the battery left no poisoned state — an ordinary
  // deposit right after must complete normally, for real, on-chain.
  const recoveryDepositHash = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'recovery-deposit',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });
  assert(recoveryDepositHash !== baselineDepositHash, 'the recovery deposit somehow produced the same hash as the baseline deposit');
  console.log(`[${logTag}] recovery deposit confirmed SUCCESS on-chain: ${recoveryDepositHash} — the app is back at a clean, usable idle state`);

  console.log(`[${logTag}] OK: all four failure modes surfaced their specific mechanism, nothing submitted, clean recovery proven`);
}

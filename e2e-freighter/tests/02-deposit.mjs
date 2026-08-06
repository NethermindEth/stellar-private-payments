// Flagship test: full deposit happy path, submitted for real (testnet).
//
// By the time run() is called, the runner has connected Freighter. The
// profile snapshot is wizard-proof (e2e-freighter/scripts/complete-
// onboarding.mjs ran once, headed, against the working profile, and that
// state — including key derivation — was baked into the snapshot; see
// scripts/verify-onboarded.mjs), so this test goes straight to the deposit
// flow. It only asserts the wizard is absent; if it unexpectedly appears,
// that invalidates the wizard-proof-snapshot premise, so this fails loudly
// rather than trying to drive the wizard itself — report via `plan deviate`.

function assert(condition, message) {
  if (!condition) throw new Error(`02-deposit: ${message}`);
}

async function assertNoOnboardingWizard(page) {
  const wizardVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (wizardVisible) {
    throw new Error(
      '02-deposit: the onboarding wizard rendered on a profile that should be wizard-proof — ' +
        'this invalidates step 1.1\'s premise (a completed, re-snapshotted profile skips the wizard). ' +
        'Report via `plan deviate` rather than driving the wizard from here.',
    );
  }
}

function parseBalance(text) {
  const match = /^(-?[\d.]+)/.exec((text || '').trim());
  return match ? Number(match[1]) : 0;
}

export async function run({ page, context, waitForAnyFreighterApproval, approveOrWatch }) {
  const approve = (kind, opts) => approveOrWatch(context, kind, opts);

  await assertNoOnboardingWizard(page);

  const balanceLocator = page.locator('#move-funds-balance');
  await balanceLocator.waitFor({ state: 'visible', timeout: 15000 });
  // The element is always visible, and its FIRST rendered value can be a
  // "—" placeholder OR a stale "0 XLM" default — both get overwritten once
  // pool config + balances finish their async load. Require the reading to
  // be non-placeholder AND stable across two consecutive polls before
  // trusting it (this account accumulates real balance across repeated
  // test runs, so a too-early "0 XLM" silently under-counts the pre-value).
  let preBalanceText = await balanceLocator.innerText();
  let stableRepeats = 0;
  const readyDeadline = Date.now() + 15000;
  while (stableRepeats < 2 && Date.now() < readyDeadline) {
    await page.waitForTimeout(500);
    const next = await balanceLocator.innerText();
    stableRepeats = next.trim() !== '—' && next.trim() === preBalanceText.trim() ? stableRepeats + 1 : 0;
    preBalanceText = next;
  }
  assert(preBalanceText.trim() !== '—', 'pool/balance data never finished loading (still "—" after 15s)');
  assert(stableRepeats >= 2, `pre-deposit balance never stabilized within 15s (last read: "${preBalanceText}")`);
  const preBalance = parseBalance(preBalanceText);
  console.log(`[02-deposit] pre-deposit balance: "${preBalanceText}" (${preBalance})`);

  const DEPOSIT_AMOUNT = 0.01;
  await page.fill('#deposit-amount', String(DEPOSIT_AMOUNT));

  const depositBtn = page.locator('#btn-deposit');
  await depositBtn.click();

  // The deployed app (not reflected in this checkout's app/js source — a
  // build/deploy drift found by screenshotting a live run, not by reading
  // source) raises a runtime confirmation dialog (role="dialog", title
  // "Confirm deposit") before actually submitting. It has no stable id, so
  // scope the button lookup to the dialog itself to avoid matching the
  // page's own "Deposit" button.
  const confirmDialog = page.getByRole('dialog').filter({ hasText: 'Confirm deposit' });
  const dialogAppeared = await confirmDialog
    .waitFor({ state: 'visible', timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (dialogAppeared) {
    await confirmDialog.getByRole('button', { name: 'Deposit', exact: true }).click();
  }

  // Track the button's own progress label (bindTxProgress in
  // app/js/ui/transactions.js writes the SDK's tx-progress messages there)
  // to prove the app advances through real stages, not just "did nothing".
  const seenStages = new Set();
  const progressDeadline = Date.now() + 120000;
  let submitted = false;

  while (Date.now() < progressDeadline) {
    const stageText = await depositBtn.locator('.btn-loading').innerText().catch(() => '');
    if (stageText) seenStages.add(stageText);

    // signMessage shouldn't appear here (key derivation already happened
    // during wizard completion) but is tolerated either way.
    const pending = await waitForAnyFreighterApproval(context, ['signMessage', 'signAuthEntry', 'signTransaction'], {
      timeoutMs: 2000,
    }).catch(() => null);
    if (pending) {
      await approve(pending.kind, { timeoutMs: 15000 });
      // A deposit can raise several sequential approvals; give the just-
      // approved popup a moment to fully close before rescanning, rather
      // than racing the next scan against its own teardown.
      await page.waitForTimeout(500);
      continue;
    }

    const toastVisible = await page.getByText(/Transaction submitted:|transactions submitted/).isVisible().catch(() => false);
    if (toastVisible) {
      submitted = true;
      break;
    }

    const stillLoading = await depositBtn.isDisabled().catch(() => false);
    if (!stillLoading && seenStages.size > 0) {
      // button re-enabled after having shown progress — treat as done even
      // if the toast already faded before we polled for it.
      submitted = true;
      break;
    }

    await page.waitForTimeout(500);
  }

  assert(seenStages.size > 0, 'deposit button never showed a progress stage — the click may not have started anything');
  console.log(`[02-deposit] progress stages seen: ${[...seenStages].join(' -> ')}`);
  assert(submitted, `deposit did not reach a submitted state within the timeout (stages seen: ${[...seenStages].join(', ')})`);

  // Balance updates on a 10s dashboard poll (app/js/ui/dashboard.js) or the
  // 'balances:updated' event — poll for the increase rather than assuming
  // either fired synchronously with the toast.
  const balanceDeadline = Date.now() + 30000;
  let postBalance = preBalance;
  let postBalanceText = preBalanceText;
  while (Date.now() < balanceDeadline) {
    postBalanceText = await balanceLocator.innerText();
    postBalance = parseBalance(postBalanceText);
    if (postBalance > preBalance) break;
    await page.waitForTimeout(1500);
  }
  console.log(`[02-deposit] post-deposit balance: "${postBalanceText}" (${postBalance})`);

  const delta = postBalance - preBalance;
  assert(
    Math.abs(delta - DEPOSIT_AMOUNT) < 1e-6,
    `balance did not increase by the deposited amount (pre=${preBalance}, post=${postBalance}, delta=${delta}, expected=${DEPOSIT_AMOUNT})`,
  );

  console.log('[02-deposit] OK: deposit submitted and balance increased by the deposited amount');
}

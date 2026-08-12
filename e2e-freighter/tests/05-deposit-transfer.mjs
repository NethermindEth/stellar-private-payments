// Compound test: deposit 0.01 XLM, then transfer 0.01 XLM to account B
// ($E2E_ACCOUNT_D_ADDRESS — provisioned, funded, and registered in the
// public-key registry by deployments/scripts/e2e-accounts-setup.sh;
// see deployments/testnet/.e2e-accounts.env). Uses the same shared
// submitAndConfirm (../src/moveFunds.mjs) as tests/04-deposit-withdraw.mjs
// — the runtime confirmation dialog, .btn-loading progress-stage tracking,
// sequential Freighter approval handling, and toast-link hash capture +
// on-chain confirmation.
//
// Transfer discovery (not in this checkout's app/js source — same
// build/deploy drift 02-deposit and 04-deposit-withdraw found): the
// recipient field is `#transfer-address` (NOT "transfer-recipient" — don't
// guess from the withdraw/deposit naming pattern). Its own runtime dialog
// is titled "Confirm transfer" with a "Transfer" confirm button. Typing a
// full 56-char address triggers an on-input registry lookup
// (app/js/ui/transactions.js's addressInput listener) that fills
// `#transfer-lookup-status` with "Found local registration" once resolved
// — this test waits for that before submitting, since RECIPIENT LOOKUP
// RESOLUTION IS THE POINT of using a registered account here (an
// unregistered recipient would fail deterministically at this stage,
// before any signing, not with a timeout).
//
// SYNC-WAIT: exactly the same situation 04-deposit-withdraw documents for
// withdraw — transfer needs the just-deposited note visible to the client
// before it can build its plan. Not gated on here either; the SDK's own
// internal retry (sdk/client/src/sync.rs) surfaces through the same
// .btn-loading progress-stage tracking submitAndConfirm already does.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('05-deposit-transfer');



export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;

  // Wizard state is per-origin: drive it on fresh origins, no-op elsewhere.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: '05-deposit-transfer' });
  // Bare APP_URL lands on Overview; Move Funds controls are hidden until
  // the tab is opened.
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const recipient = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(recipient, 'E2E_ACCOUNT_D_ADDRESS is not set — source deployments/testnet/.e2e-accounts.env first');

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const logTag = '05-deposit-transfer';

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

  // Switch tabs via the stable data attribute — plain text "Transfer" is
  // safe here (no known duplicate elsewhere), but stay consistent with
  // deposit/withdraw's proven pattern.
  await page.locator('[data-move-flow="transfer"]').click();
  await page.waitForTimeout(500);

  const transferHash = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'transfer',
    amountSelector: '#transfer-amount',
    submitSelector: '#btn-transfer',
    confirmDialogTitle: 'Confirm transfer',
    confirmButtonLabel: 'Transfer',
    amount: '0.01',
    rpcUrl,
    // Generous: the just-deposited note may need the SDK's own sync-wait
    // retry before a transfer plan can build (same as withdraw).
    progressTimeoutMs: 180000,
    fillBeforeSubmit: async () => {
      await page.fill('#transfer-address', recipient);
      const statusLocator = page.locator('#transfer-lookup-status');
      const resolved = await statusLocator
        .filter({ hasText: 'Found local registration' })
        .waitFor({ state: 'visible', timeout: 15000 })
        .then(() => true)
        .catch(() => false);
      if (!resolved) {
        const status = await statusLocator.innerText().catch(() => '(unavailable)');
        const warning = await page.locator('#transfer-lookup-warning').innerText().catch(() => '(unavailable)');
        assert(
          false,
          `recipient registry lookup did not resolve to "Found local registration" within 15s ` +
            `(status: "${status}", warning: "${warning}") — this points at a registration problem with ` +
            `${recipient}, not a timing issue; re-run deployments/scripts/e2e-accounts-setup.sh ` +
            `(--verify) rather than retrying blindly`,
        );
      }
    },
  });

  assert(depositHash !== transferHash, 'deposit and transfer somehow produced the same transaction hash');
  log.info('OK: deposit', depositHash.slice(0, 8), 'and transfer', transferHash.slice(0, 8), 'both confirmed SUCCESS on-chain');
}
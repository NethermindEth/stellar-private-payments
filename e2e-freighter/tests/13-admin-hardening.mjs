// Admin-page coverage: initialization, contract state, a real testnet connect,
// the ASP secret masked and cleared after a failed submission, and an account
// switch ending the session.
//
// Neither E2E account is the deployed ASP administrator, so this does not
// exercise a successful privileged write.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { expectNoFreighterApproval, switchFreighterAccount } from '../src/wallet.mjs';

const log = createLogger('13-admin-hardening');

async function text(page, selector) {
  return (await page.locator(selector).textContent().catch(() => '')).trim();
}

async function waitForText(page, selector, predicate, operation, timeoutMs = 60_000) {
  return waitForCondition({
    operation,
    timeoutMs,
    intervalMs: 200,
    observe: () => text(page, selector),
    isReady: predicate,
  }).then((result) => result.value);
}

export async function run({ page, context, approveOrWatch }) {
  const appUrl = process.env.APP_URL;
  assert(appUrl, 'APP_URL is required');

  await page.goto(new URL('/admin.html', appUrl).href);
  await page.waitForLoadState('domcontentloaded');

  const initialStatus = await waitForText(
    page,
    '#status',
    (value) => value === 'Ready' || value === 'Init failed',
    'admin:initialization',
  );
  assert(initialStatus === 'Ready', `admin page did not initialize successfully; status was '${initialStatus}'`);

  const membershipContract = await page.locator('#membershipContract').inputValue();
  const nonMembershipContract = await page.locator('#nonMembershipContract').inputValue();
  assert(/^C[A-Z2-7]{55}$/.test(membershipContract), 'membership contract state was not loaded');
  assert(/^C[A-Z2-7]{55}$/.test(nonMembershipContract), 'non-membership contract state was not loaded');

  const secretInput = page.locator('#allowlistAspSecret');
  assert(await secretInput.getAttribute('type') === 'password', 'ASP secret input is not masked');
  assert(
    await secretInput.getAttribute('autocomplete') === 'new-password',
    'ASP secret input may be offered for saving or restoration',
  );

  await page.locator('#connectBtn').click();
  await approveOrWatch(context, 'connect', { timeoutMs: 8_000 }).catch(() => {});
  const walletChip = await waitForText(
    page,
    '#walletChip',
    (value) => value !== 'Connect Freighter',
    'admin:wallet-connect',
  );
  assert(/^G[A-Z2-7]{5}\.\.\.[A-Z2-7]{4}$/.test(walletChip), `admin wallet chip is not an address; got '${walletChip}'`);
  assert(await text(page, '#networkChip') === 'TESTNET', 'admin page did not retain the real Freighter testnet network');
  assert(!(await page.locator('#addToAllowlistBtn').isDisabled()), 'connected admin write controls stayed disabled');

  // A validation failure happens before any signing request, but still runs
  // insertMembershipLeaf()'s finally block. This is deterministic evidence
  // that a secret does not survive an unsuccessful submission.
  await page.locator('[data-target="allowlist"]').click();
  await secretInput.fill('0x02');
  await page.locator('#addToAllowlistBtn').click();
  await expectNoFreighterApproval(context, ['signTransaction', 'signAuthEntry'], { timeoutMs: 1_500 });
  await waitForText(
    page,
    '#status',
    (value) => value === 'Allowlist insert failed',
    'admin:failed-insert',
    10_000,
  );
  assert(await secretInput.inputValue() === '', 'ASP secret survived a failed allowlist submission');

  // The restored profile starts on Account 2 and also contains Account 3.
  // Leave another secret in the form, switch accounts in Freighter, and let
  // admin.js's shared watcher prove that it closes the session and clears it.
  await secretInput.fill('0x03');
  await switchFreighterAccount(context, 'Account 3');
  // switchFreighterAccount necessarily leaves the extension tab in front.
  // Return to the app just as a user does after choosing the account; this
  // also ensures the assertion is about the page once it is active again,
  // not about Chrome's treatment of a hidden tab's timers.
  await page.bringToFront();
  await waitForText(
    page,
    '#walletChip',
    (value) => value === 'Connect Freighter',
    'admin:account-change-disconnect',
    10_000,
  );
  assert(await secretInput.inputValue() === '', 'ASP secret survived watcher-driven disconnect');
  assert(await page.locator('#addToAllowlistBtn').isDisabled(), 'write controls remained enabled after account change');

  log.info(
    'OK: admin initialized and connected; failed-submit and account-change paths cleared the secret and disabled writes',
  );
}

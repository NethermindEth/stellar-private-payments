#!/usr/bin/env node
// Provision a Freighter Chrome profile for e2e tests.
//
// Merges the former setup-freighter-profile.mjs, complete-onboarding.mjs,
// verify-onboarded.mjs and add-account.mjs into a single script.
//
// Steps:
//   1. Create/import the Freighter wallet (setup-freighter-profile.mjs)
//   2. Import account D, the signing account, and make C active again
//   3. Drive the app's onboarding wizard (complete-onboarding.mjs)
//   4. Verify the result (verify-onboarded.mjs)
//
// The caller (provision.sh) handles snapshots and restore paths.

import '../src/env.mjs';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scrub } from '../src/redact.mjs';
import {
  launch,
  unlockFreighter,
  connectApp,
  waitForFreighterApproval,
  approveOrWatch,
} from '../src/runner.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { requireAppUrl } from '../src/env.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(PKG_ROOT, '..');
const PROFILE_DIR = path.join(PKG_ROOT, '.chrome-profile');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';

const args = process.argv.slice(2);
const VERIFY_ONLY = args.includes('--verify');
const SKIP_WIZARD = args.includes('--skip-wizard');

// ── Freighter UI selectors ──
// Freighter's first-run screen offers no import path: you create a wallet with
// its own generated mnemonic, then import the account under test as a SECOND
// wallet via add-wallet. Driving it any other way does not work.
const SEL = {
  // Unlocking an already-provisioned profile
  unlockPasswordInput: '#password-input',
  unlockButtonText: 'Unlock',

  // First-run wallet creation (throwaway mnemonic)
  createNewWalletText: 'Create new wallet',
  newPasswordInput: '#new-password-input',
  confirmPasswordInput: '#confirm-password-input',
  termsCheckbox: '#termsOfUse-input',
  confirmText: 'Confirm',
  skipBackupText: 'Do this later',

  // Network selection
  networkSelectorOpen: '[data-testid="network-selector-open"]',
  testNetText: 'Test Net',

  // Adding / importing a wallet
  firstAccountText: 'Account 1',
  accountName: '[data-testid="account-view-account-name"]',
  addWallet: '[data-testid="add-wallet"]',
  importSecretKeyText: 'Import Stellar Secret Key',
  privateKeyInput: '#privateKey-input',
  passwordInput: '#password-input',
  authorizationCheckbox: '#authorization-input',
  importText: 'Import',

  // Sidebar mode — runner.mjs's approval-URL discovery depends on this being on
  accountHeaderIconBtn: '[data-testid="AccountHeader__icon-btn"]',
  sidebarModeText: 'Sidebar mode',
};

// ── Helpers ──
function step(msg) {
  console.error('==>', msg);
}

function getRequiredEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

// Reuse the app tab instead of stacking a new one per stage. Extra pages are
// not merely untidy: waitForFreighterApproval scans context.pages() to find
// the approval popup, so every abandoned tab is another candidate it can latch
// onto — and a fresh load re-renders the app's modals, which then intercept
// clicks meant for the page underneath.
async function appPage(context) {
  const appOrigin = new URL(requireAppUrl()).origin;
  return context.pages().find((p) => p.url().startsWith(appOrigin)) || (await context.newPage());
}

// Every G... address the extension has stored. Used to prove an import
// actually landed rather than trusting that the clicks went through.
async function readStoredAddresses(page) {
  const storage = await page.evaluate(
    () => new Promise((resolve) => chrome.storage.local.get(null, resolve)),
  );
  return [...new Set(JSON.stringify(storage).match(/G[A-Z2-7]{55}/g) || [])];
}

// Drives add-wallet -> Import Stellar Secret Key -> submit. Assumes the
// account list is already open, since how you open it differs between the
// first import (header still reads "Account 1") and later ones.
async function importSecretKeyFlow(page, secret, password) {
  await page.click(SEL.addWallet);
  await page.waitForTimeout(600);
  await page.getByText(SEL.importSecretKeyText, { exact: true }).click();
  await page.waitForTimeout(600);
  await page.fill(SEL.privateKeyInput, secret);
  await page.fill(SEL.passwordInput, password);
  await page.check(SEL.authorizationCheckbox, { force: true });
  await page.getByText(SEL.importText, { exact: true }).click();
  await page.waitForTimeout(1200);
}

// ── Step 1: Provision Freighter profile ──
async function provisionFreighter(context) {
  step('setting up Freighter extension');
  const page = await context.newPage();
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);

  await page.waitForTimeout(1000);

  const password = getRequiredEnv('E2E_FREIGHTER_PASSWORD');

  // 1. Create Freighter's own wallet. Its mnemonic is throwaway — only the
  //    account imported in step 3 matters.
  await page.getByText(SEL.createNewWalletText, { exact: true }).click();
  await page.waitForTimeout(600);
  await page.fill(SEL.newPasswordInput, password);
  await page.fill(SEL.confirmPasswordInput, password);
  await page.check(SEL.termsCheckbox, { force: true });
  await page.getByText(SEL.confirmText, { exact: true }).click();
  await page.waitForTimeout(1000);
  await page.getByText(SEL.skipBackupText, { exact: true }).click();
  await page.waitForTimeout(1200);

  // The "You're all set" splash left after onboarding has no account UI;
  // re-navigating to the bare page routes to the actual home/account view.
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1200);

  // 2. Switch to Test Net.
  await page.click(SEL.networkSelectorOpen);
  await page.waitForTimeout(400);
  await page.getByText(SEL.testNetText, { exact: true }).click();
  await page.waitForTimeout(800);

  // 3. Import the funded account under test as a second wallet. The header
  //    still reads "Account 1" here — the throwaway from step 1.
  await page.getByText(SEL.firstAccountText, { exact: true }).click();
  await page.waitForTimeout(600);
  await importSecretKeyFlow(page, getRequiredEnv('E2E_ACCOUNT_C_SECRET'), password);

  // 4. Enable sidebar mode.
  await page.click(SEL.accountHeaderIconBtn);
  await page.waitForTimeout(300);
  await page.getByText(SEL.sidebarModeText, { exact: true }).first().click({ force: true });
  await page.waitForTimeout(500);

  // 5. Prove the import landed rather than assuming the clicks worked.
  const expected = process.env.E2E_ACCOUNT_C_ADDRESS;
  if (expected) {
    const addresses = await readStoredAddresses(page);
    if (!addresses.includes(expected)) {
      throw new Error(
        `imported account address not found in extension storage; expected ${expected}, saw ${addresses.join(', ') || '(none)'}`,
      );
    }
  }

  step('Freighter wallet created and account imported');
  await page.close();
}

const shortAddress = (address) => `${address.slice(0, 4)}…${address.slice(-4)}`;

// The row for `address` in Freighter's account list, which it opens, or null.
// Freighter keeps account keys encrypted, so this list, which names each
// account by its shortened address, is where a held account shows.
async function freighterAccountRow(page, address) {
  await page.click(SEL.accountName, { force: true });
  const rows = page.locator('.detail-name');
  await rows.first().waitFor({ state: 'visible', timeout: 10_000 });
  for (let i = 0; i < (await rows.count()); i += 1) {
    // The name and the shortened address are siblings under the row.
    if ((await rows.nth(i).locator('xpath=../..').innerText()).includes(shortAddress(address))) {
      return rows.nth(i);
    }
  }
  return null;
}

// Make `address` Freighter's active account, and prove it took.
async function selectFreighterAccount(page, address) {
  const short = shortAddress(address);
  const row = await freighterAccountRow(page, address);
  if (!row) throw new Error(`no Freighter account row shows ${short}`);
  await row.click({ force: true });

  const deadline = Date.now() + 10_000;
  let active = null;
  while (Date.now() < deadline) {
    ({ lastUsedAccount: active } = await page.evaluate(
      () => new Promise((resolve) => chrome.storage.local.get('lastUsedAccount', resolve)),
    ));
    if (active === address) return;
    await page.waitForTimeout(200);
  }
  throw new Error(`could not make ${short} the active Freighter account; active is ${active || '(none)'}`);
}

// ── Step 2: Import account D, the signing account ──
// Test 12 signs with D for C's notes, so Freighter must hold D, and must have
// connected D to the app: Freighter will not sign as an account the site is not
// connected to, and it connects only the active account. Importing makes D
// active, so the app is connected while it is, and C is made active again
// before the wizard runs, since the app takes the active account as the note
// owner when it first connects.
async function importSigningAccount(context) {
  step('importing account D (E2E_ACCOUNT_D)');
  const page = await context.newPage();
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1000);

  // Open the account list. Unlike the first import, the header no longer
  // reads "Account 1" by this point, so go via the testid rather than text.
  await page.click(SEL.accountName, { force: true });
  await page.waitForTimeout(500);

  await importSecretKeyFlow(
    page,
    getRequiredEnv('E2E_ACCOUNT_D_SECRET'),
    getRequiredEnv('E2E_FREIGHTER_PASSWORD'),
  );

  // Selecting C also proves D landed: its row is listed beside C's.
  const signer = getRequiredEnv('E2E_ACCOUNT_D_ADDRESS');
  if (!(await freighterAccountRow(page, signer))) {
    throw new Error(`imported account D not listed in Freighter; expected ${shortAddress(signer)}`);
  }
  step('account D imported');

  await connectSigningAccount(context);

  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1000);
  await selectFreighterAccount(page, getRequiredEnv('E2E_ACCOUNT_C_ADDRESS'));
  step('account C active again');
  await page.close();
}

// Connect the app while D is active, then close the onboarding it opens for D.
// Freighter keeps D connected to the app; the app keeps no note owner, because
// it remembers one only once connecting succeeds.
async function connectSigningAccount(context) {
  step('connecting account D to the app');
  const page = await appPage(context);
  await connectApp(page, { appUrl: requireAppUrl(), context });
  if (await page.locator('#onboarding-close-btn').isVisible().catch(() => false)) {
    await page.locator('#onboarding-close-btn').click();
  }
  await page.locator('#wallet-btn').waitFor({ state: 'visible', timeout: 15_000 });
  const remembered = await page.evaluate(() => localStorage.getItem('poolstellar_note_owner'));
  if (remembered) {
    throw new Error(`connecting account D left ${remembered} as the app's note owner`);
  }
  step('account D connected to the app');
}

// ── Step 3: Complete onboarding wizard ──
async function completeWizard(context) {
  step('completing the app onboarding wizard (headed)');
  const page = await appPage(context);
  const appUrl = requireAppUrl();
  await connectApp(page, { appUrl, context });

  // driveWizard calls both of these; passing null made it die with
  // "waitForFreighterApproval is not a function" the moment the wizard
  // reached its signMessage step. Both are exported by runner.mjs.
  await driveWizard(page, context, {
    waitForFreighterApproval,
    approveOrWatch,
    logTag: 'provision',
  });

  // Verify the wizard actually completed
  const stillVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (stillVisible) throw new Error('provision: onboarding modal still visible after driving all steps');

  step('onboarding wizard completed');
}

// ── Step 4: Verify the profile ──
async function verifyProfile(context) {
  step('verifying the provisioned profile');
  const page = await appPage(context);

  // Connect, rather than expecting the app to already be connected: the app
  // shows "Connect Freighter" on every fresh page load until it is clicked,
  // even when Freighter would auto-approve the origin. Asserting the button
  // is absent without clicking it can never pass.
  await connectApp(page, { appUrl: requireAppUrl(), context });

  // Test 12 signs with account D for account C's notes: Freighter must hold D,
  // and the app must own notes as C. Later runs connect as the owner the app
  // remembers, so a profile onboarded as D fails every signing-account test.
  const owner = getRequiredEnv('E2E_ACCOUNT_C_ADDRESS');
  const remembered = await page.evaluate(() => localStorage.getItem('poolstellar_note_owner'));
  if (remembered !== owner) {
    throw new Error(`verify: the app's note owner is ${remembered || '(none)'}, not account C (${owner})`);
  }
  const extension = await context.newPage();
  await extension.goto(`chrome-extension://${EXT_ID}/index.html`);
  await extension.waitForTimeout(1000);
  const signer = getRequiredEnv('E2E_ACCOUNT_D_ADDRESS');
  const holdsSigner = Boolean(await freighterAccountRow(extension, signer));
  await extension.close();
  if (!holdsSigner) {
    throw new Error(`verify: Freighter does not hold account D (${signer}); rebuild with setup.sh --force`);
  }

  // What actually matters is that the wizard completion persisted — that is
  // the thing every later headless run depends on skipping.
  const wizard = await page.evaluate(() => ({
    visible: !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
    // The wizard marks each step pending/done from the same gates that decide
    // whether it opens at all, so this names which gate re-fired.
    pending: [...document.querySelectorAll('#onboarding-steps [data-step]')]
      .filter((el) => el.dataset.state === 'pending')
      .map((el) => el.dataset.step),
  }));
  if (wizard.visible) {
    throw new Error(
      `verify: onboarding wizard rendered after connecting — unsatisfied step(s): ${wizard.pending.join(', ') || 'unknown'}`,
    );
  }

  // And that the app is actually usable, not merely un-blocked. The deposit
  // form lives on the Move Funds panel, which is a view switch rather than a
  // route, so click the nav — reloading with a #move-funds fragment would
  // re-render the app's modals and put an overlay back over the page.
  await page.click('[data-view="move-funds"]');
  await page.locator('#btn-deposit').waitFor({ state: 'visible', timeout: 15000 });

  step('profile verified: connected, no wizard, deposit form reachable');
}

// ── Main ──
async function main() {
  if (VERIFY_ONLY) {
    // Just verify without provisioning
    const context = await launch({ userDataDir: PROFILE_DIR, headless: true });
    try {
      await unlockFreighter(context);
      await verifyProfile(context);
    } finally {
      await context.close();
    }
    return;
  }

  // Full provisioning
  const context = await launch({ userDataDir: PROFILE_DIR, headless: false });
  try {
    await unlockFreighter(context);
    await provisionFreighter(context);
    await importSigningAccount(context);

    if (!SKIP_WIZARD) {
      await completeWizard(context);
    }

    await verifyProfile(context);
  } finally {
    await context.close();
  }

  step('provisioning complete — run provision.sh to snapshot');
}

main().catch((err) => {
  console.error('provision: FAILED —', scrub(err.message));
  process.exit(1);
});
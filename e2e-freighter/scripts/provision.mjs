#!/usr/bin/env node
// Provision a Freighter Chrome profile for e2e tests.
//
// Merges the former setup-freighter-profile.mjs, complete-onboarding.mjs,
// verify-onboarded.mjs and add-account.mjs into a single script.
//
// Steps:
//   1. Create/import the Freighter wallet (setup-freighter-profile.mjs)
//   2. If --add-account: import account B (add-account.mjs)
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
  switchFreighterAccount,
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
const ADD_ACCOUNT = args.includes('--add-account');
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

// ── Step 2: Import account B (add-account.mjs) ──
async function importAccountB(context) {
  step('importing account B (E2E_ACCOUNT_D)');
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

  step('account B imported');
  await page.close();
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

  // What actually matters is that the wizard completion persisted — that is
  // the thing every later headless run depends on skipping.
  const wizardVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (wizardVisible) {
    throw new Error('verify: onboarding wizard rendered after connecting — completion did not persist into the profile');
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

    if (ADD_ACCOUNT) {
      await importAccountB(context);
    }

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
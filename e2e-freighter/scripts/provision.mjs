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
import { launch, unlockFreighter, switchFreighterAccount, connectApp } from '../src/runner.mjs';
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

// ── Freighter UI selectors (discovered by manually driving the extension) ──
const SEL = {
  unlockPasswordInput: '#password-input',
  unlockButtonText: 'Unlock',
  importRadio: 'input[type="radio"][value="import"]',
  importSecretKeyLabel: 'Import Stellar Secret Key',
  secretKeyInput: 'textarea[placeholder="Paste your secret key"]',
  passwordInput: '#password-input',
  confirmPasswordInput: '#confirm-password-input',
  termsCheckbox: '[data-testid="wallet-creation-terms-of-use-checkbox"]',
  submitButton: 'button[type="submit"]',
  gotItButton: 'button:has-text("Got it")',
  accountName: '[data-testid="account-view-account-name"]',
  // Add-account selectors
  addAnotherWallet: 'text=Add another wallet',
  importSecretKey: 'text=Import Stellar Secret Key',
  detailName: '.detail-name',
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

// ── Step 1: Provision Freighter profile ──
async function provisionFreighter(context) {
  step('setting up Freighter extension');
  const page = await context.newPage();
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);

  // Wait for the welcome page to load
  await page.waitForTimeout(2000);

  // Select "Import Stellar Secret Key"
  await page.click(SEL.importRadio);
  await page.click(`text=${SEL.importSecretKeyLabel}`);

  // Fill in the secret key
  const secret = getRequiredEnv('E2E_ACCOUNT_C_SECRET');
  await page.fill(SEL.secretKeyInput, secret);

  // Fill in password
  const password = getRequiredEnv('E2E_FREIGHTER_PASSWORD');
  await page.fill(SEL.passwordInput, password);
  await page.fill(SEL.confirmPasswordInput, password);

  // Accept terms
  await page.click(SEL.termsCheckbox);
  await page.click(SEL.submitButton);
  await page.waitForTimeout(2000);

  // Dismiss "Got it"
  const gotIt = page.locator(SEL.gotItButton);
  if (await gotIt.isVisible().catch(() => false)) {
    await gotIt.click();
    await page.waitForTimeout(500);
  }

  step('Freighter wallet created');
  return page;
}

// ── Step 2: Import account B (add-account.mjs) ──
async function importAccountB(context) {
  step('importing account B (E2E_ACCOUNT_D)');
  const page = await context.newPage();
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1000);

  // Open account list
  await page.click(SEL.accountName, { force: true });
  await page.waitForTimeout(500);

  // Click "Add another wallet"
  await page.click(SEL.addAnotherWallet);
  await page.waitForTimeout(500);

  // Click "Import Stellar Secret Key"
  await page.click(SEL.importSecretKey);
  await page.waitForTimeout(500);

  // Fill secret and password
  const secret = getRequiredEnv('E2E_ACCOUNT_D_SECRET');
  const password = getRequiredEnv('E2E_FREIGHTER_PASSWORD');
  await page.fill(SEL.secretKeyInput, secret);
  await page.fill(SEL.passwordInput, password);
  await page.click(SEL.submitButton);
  await page.waitForTimeout(1500);

  step('account B imported');
  return page;
}

// ── Step 3: Complete onboarding wizard ──
async function completeWizard(context) {
  step('completing the app onboarding wizard (headed)');
  const page = await context.newPage();
  const appUrl = requireAppUrl();
  await connectApp(page, { appUrl, context });

  await driveWizard(page, context, {
    waitForFreighterApproval: null, // runner's function, not available here
    approveOrWatch: null,
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
  step('verifying a restored copy');
  // Try to launch and connect to the app
  const page = await context.newPage();
  const appUrl = requireAppUrl();
  await page.goto(appUrl);
  await page.waitForTimeout(2000);

  // Check that the "Connect Freighter" button is gone
  const connectBtnVisible = await page
    .getByText('Connect Freighter', { exact: true })
    .isVisible()
    .catch(() => false);
  if (connectBtnVisible) {
    throw new Error('verify: "Connect Freighter" is still visible — the snapshot may not have the connected state');
  }

  step('profile verified: connected, address shown, network is TESTNET');
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
  console.error('provision: FAILED —', err.message);
  process.exit(1);
});
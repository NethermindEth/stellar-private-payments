#!/usr/bin/env node
import '../src/env.mjs';
// Scripted, unattended Freighter provisioning in a fresh Chrome profile.
//
// Given env vars (E2E_ACCOUNT_C_SECRET / E2E_ACCOUNT_C_ADDRESS, sourced from
// deployments/testnet/.e2e-accounts.env, and E2E_FREIGHTER_PASSWORD), this:
//   1. launches Chrome with the vendored unpacked Freighter extension
//      (e2e-freighter/vendor/freighter/) loaded via --load-extension
//   2. creates a fresh Freighter wallet (its own generated mnemonic — the
//      wallet's own seed is throwaway, only the imported account matters)
//   3. switches the network to Test Net
//   4. imports E2E_ACCOUNT_C_SECRET as a second wallet via Freighter's
//      "Import Stellar Secret Key" flow
//   5. enables sidebar mode
//   6. closes and relaunches the SAME profile dir, then scripts the unlock
//      screen — proving the vault persists across a restart
//   7. prints the imported account's address (read from chrome.storage.local,
//      since Freighter never renders the full address as plain text)
//
// Freighter's onboarding DOM is undocumented and has no stable data-testids
// on most onboarding steps; selectors here were discovered by manually
// driving the flow once and are the brittle part of this script — re-verify
// them if the vendored extension version (vendor/freighter/manifest.json)
// changes.
//
// Usage:
//   set -a; . deployments/testnet/.e2e-accounts.env; set +a
//   E2E_FREIGHTER_PASSWORD=... node e2e-freighter/scripts/setup-freighter-profile.mjs [--verify-only]

import { chromium } from 'playwright';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const EXT_PATH = path.resolve(__dirname, '..', 'vendor', 'freighter');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';
const PROFILE_DIR = path.join(REPO_ROOT, 'e2e-freighter', '.chrome-profile');
const CHROMIUM_PATH = process.env.E2E_CHROMIUM_PATH || '/usr/bin/chromium';

const VERIFY_ONLY = process.argv.includes('--verify-only');

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`setup-freighter-profile: missing required env var ${name}`);
    process.exit(1);
  }
  return value;
}

const SECRET = requireEnv('E2E_ACCOUNT_C_SECRET');
const EXPECTED_ADDRESS = requireEnv('E2E_ACCOUNT_C_ADDRESS');
const PASSWORD = requireEnv('E2E_FREIGHTER_PASSWORD');

if (!fs.existsSync(path.join(EXT_PATH, 'manifest.json'))) {
  console.error(`setup-freighter-profile: no vendored extension at ${EXT_PATH}`);
  console.error('run: cp -r "<chrome profile>/Extensions/bcacfldlkkdogcmkkibnjlakofdplcbk/<version>" e2e-freighter/vendor/freighter');
  process.exit(1);
}

async function launch(profileDir) {
  return chromium.launchPersistentContext(profileDir, {
    headless: false,
    executablePath: CHROMIUM_PATH,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
    ],
  });
}

async function extensionPage(context) {
  await new Promise((r) => setTimeout(r, 1500));
  // On launch, Chrome auto-opens the extension pinned at `#/welcome`
  // regardless of actual account state (a Freighter quirk: that hash route
  // never redirects even when accounts already exist). Navigating to the
  // bare index.html with no hash lets its router pick the correct screen
  // (welcome for a brand-new profile, unlock-account for an existing one).
  const existing = context.pages().find((p) => p.url().includes(EXT_ID));
  const page = existing || (await context.newPage());
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  return page;
}

async function readStoredAddress(page) {
  const storage = await page.evaluate(
    () => new Promise((resolve) => chrome.storage.local.get(null, resolve)),
  );
  const matches = [...new Set(JSON.stringify(storage).match(/G[A-Z2-7]{55}/g) || [])];
  return matches;
}

async function provision() {
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  const context = await launch(PROFILE_DIR);
  const page = await extensionPage(context);
  await page.waitForTimeout(1000);

  // 1. Create wallet (Freighter's own generated mnemonic; throwaway).
  await page.getByText('Create new wallet', { exact: true }).click();
  await page.waitForTimeout(600);
  await page.fill('#new-password-input', PASSWORD);
  await page.fill('#confirm-password-input', PASSWORD);
  await page.check('#termsOfUse-input', { force: true });
  await page.getByText('Confirm', { exact: true }).click();
  await page.waitForTimeout(1000);
  await page.getByText('Do this later', { exact: true }).click();
  await page.waitForTimeout(1200);
  // The "You're all set" splash left after onboarding has no account UI;
  // re-navigating to the bare page routes to the actual home/account view.
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1200);

  // 2. Switch to Test Net.
  await page.click('[data-testid="network-selector-open"]');
  await page.waitForTimeout(400);
  await page.getByText('Test Net', { exact: true }).click();
  await page.waitForTimeout(800);

  // 3. Import the throwaway funded account via its secret key.
  await page.getByText('Account 1', { exact: true }).click();
  await page.waitForTimeout(600);
  await page.click('[data-testid="add-wallet"]');
  await page.waitForTimeout(600);
  await page.getByText('Import Stellar Secret Key', { exact: true }).click();
  await page.waitForTimeout(600);
  await page.fill('#privateKey-input', SECRET);
  await page.fill('#password-input', PASSWORD);
  await page.check('#authorization-input', { force: true });
  await page.getByText('Import', { exact: true }).click();
  await page.waitForTimeout(1200);

  // 4. Enable sidebar mode.
  await page.click('[data-testid="AccountHeader__icon-btn"]');
  await page.waitForTimeout(300);
  await page.getByText('Sidebar mode', { exact: true }).first().click({ force: true });
  await page.waitForTimeout(500);

  const addresses = await readStoredAddress(page);
  if (!addresses.includes(EXPECTED_ADDRESS)) {
    throw new Error(
      `imported account address not found in extension storage; expected ${EXPECTED_ADDRESS}, saw ${addresses.join(', ')}`,
    );
  }

  await context.close();
  return addresses;
}

async function verifyUnlockSurvivesRestart() {
  const context = await launch(PROFILE_DIR);
  const page = await extensionPage(context);
  await page.waitForTimeout(1000);
  // Freighter locks on every fresh browser launch; prove scripted unlock works.
  await page.fill('#password-input', PASSWORD);
  await page.getByText('Unlock', { exact: true }).click();
  await page.waitForTimeout(1200);

  const addresses = await readStoredAddress(page);
  await context.close();
  return addresses;
}

async function main() {
  // --verify-only reuses an existing profile if present (proving unlock
  // survives a restart without re-provisioning); without a profile yet, or
  // without the flag, it provisions fresh first — both paths always finish
  // with the restart+unlock proof below.
  const hasProfile = fs.existsSync(PROFILE_DIR);
  if (!VERIFY_ONLY || !hasProfile) {
    await provision();
  }
  const addresses = await verifyUnlockSurvivesRestart();

  if (!addresses.includes(EXPECTED_ADDRESS)) {
    throw new Error(
      `imported account address missing after restart+unlock; expected ${EXPECTED_ADDRESS}, saw ${addresses.join(', ')}`,
    );
  }
  console.log(EXPECTED_ADDRESS);
}

main().catch((err) => {
  console.error('setup-freighter-profile: FAILED:', err.message);
  process.exit(1);
});

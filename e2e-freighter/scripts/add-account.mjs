#!/usr/bin/env node
import '../src/env.mjs';
// Import a second Stellar account (E2E_ACCOUNT_D_SECRET) into the LIVE
// working Freighter profile (e2e-freighter/.chrome-profile — the same
// profile scripts/setup-freighter-profile.mjs built and
// scripts/complete-onboarding.mjs already onboarded against), so both A
// and B live in one Chromium profile as separate Freighter "wallets".
//
// Reuses the exact import flow scripts/setup-freighter-profile.mjs already
// proved (steps discovered by manually driving Freighter's UI once): open
// the account list via the current account name, "Add another wallet",
// "Import Stellar Secret Key", fill secret + password, accept, confirm.
//
// Run once against the live profile, then re-snapshot with
// scripts/snapshot-profile.sh so every future restore already has both
// accounts.
//
// Usage:
//   set -a; . deployments/testnet/.e2e-accounts.env; set +a
//   node e2e-freighter/scripts/add-account.mjs

import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { launch, unlockFreighter } from '../src/runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PROFILE_DIR = path.join(REPO_ROOT, 'e2e-freighter', '.chrome-profile');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`add-account: missing required env var ${name}`);
    process.exit(1);
  }
  return value;
}

const SECRET = requireEnv('E2E_ACCOUNT_D_SECRET');
const EXPECTED_ADDRESS = requireEnv('E2E_ACCOUNT_D_ADDRESS');
const PASSWORD = requireEnv('E2E_FREIGHTER_PASSWORD');

if (!fs.existsSync(PROFILE_DIR)) {
  console.error(`add-account: no live profile at ${PROFILE_DIR}; run scripts/setup-freighter-profile.mjs first`);
  process.exit(1);
}

async function readStoredAddresses(page) {
  const storage = await page.evaluate(
    () => new Promise((resolve) => chrome.storage.local.get(null, resolve)),
  );
  return [...new Set(JSON.stringify(storage).match(/G[A-Z2-7]{55}/g) || [])];
}

async function main() {
  const context = await launch({ userDataDir: PROFILE_DIR, headless: false });
  const page = await unlockFreighter(context);
  await page.waitForTimeout(1000);

  const before = await readStoredAddresses(page);
  if (before.includes(EXPECTED_ADDRESS)) {
    console.log(`add-account: ${EXPECTED_ADDRESS} already present in this profile, nothing to do`);
    await context.close();
    return;
  }

  // Open the account list via the current account's name (same click
  // setup-freighter-profile.mjs uses before its own import), then the
  // "add another wallet" affordance and import flow.
  await page.click('[data-testid="account-view-account-name"]', { force: true });
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

  const after = await readStoredAddresses(page);
  if (!after.includes(EXPECTED_ADDRESS)) {
    throw new Error(
      `add-account: imported account address not found in extension storage after import; expected ${EXPECTED_ADDRESS}, saw ${after.join(', ')}`,
    );
  }

  await context.close();
  console.log(`add-account: OK — ${EXPECTED_ADDRESS} imported into the live profile`);
  console.log('add-account: re-run scripts/snapshot-profile.sh to bake this into profile-snapshot.tar.gz');
}

main().catch((err) => {
  console.error('add-account: FAILED:', err.message);
  process.exit(1);
});

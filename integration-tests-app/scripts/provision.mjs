#!/usr/bin/env node
// Provision a Freighter Chrome profile for e2e tests: create the wallet,
// switch to the local quickstart network, enable sidebar mode. No test
// account is baked in — runner.mjs imports a fresh ephemeral one per test.
// The caller (provision.sh) handles snapshots and restore paths.

import '../src/env.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scrub } from '../src/redact.mjs';
import { launch, unlockFreighter, connectApp } from '../src/runner.mjs';
import { importAccount } from '../src/wallet.mjs';
import {
  FRIENDBOT_URL,
  NETWORK_PASSPHRASE,
  RPC_URL,
  createAccount,
  fund,
  seedDriverOnboarding,
} from '../src/testAccount.mjs';
import { requireAppUrl } from '../src/env.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
// --verify targets a restored temp copy (E2E_CHROME_USER_DATA_DIR, set by
// provision.sh), not the master profile — verifying in place would import a
// second wallet into the exact directory the next snapshot is tar'd from.
const PROFILE_DIR = process.env.E2E_CHROME_USER_DATA_DIR || path.join(PKG_ROOT, '.chrome-profile');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';

const LOCAL_NETWORK = {
  name: 'Local Quickstart',
  horizonUrl: 'http://localhost:8000',
  rpcUrl: RPC_URL,
  passphrase: NETWORK_PASSPHRASE,
  friendbotUrl: FRIENDBOT_URL,
};

const VERIFY_ONLY = process.argv.includes('--verify');

const SEL = {
  createNewWalletText: 'Create new wallet',
  newPasswordInput: '#new-password-input',
  confirmPasswordInput: '#confirm-password-input',
  termsCheckbox: '#termsOfUse-input',
  confirmText: 'Confirm',
  skipBackupText: 'Do this later',
  networkNameInput: '#networkName',
  networkHorizonUrlInput: '#networkUrl',
  networkRpcUrlInput: '#sorobanRpcUrl',
  networkPassphraseInput: '#networkPassphrase',
  networkFriendbotUrlInput: '#friendbotUrl',
  networkAllowHttpCheckbox: '#isAllowHttpSelected-input',
  networkSwitchToItCheckbox: '#isSwitchSelected-input',
  networkFormAddButton: '[data-testid="NetworkForm__add"]',
  accountHeaderIconBtn: '[data-testid="AccountHeader__icon-btn"]',
  sidebarModeText: 'Sidebar mode',
};

function step(msg) {
  console.error('==>', msg);
}

function getRequiredEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

// ── Provision the Freighter extension: wallet + network + sidebar mode ──
async function provisionFreighter(context) {
  step('setting up Freighter extension');
  const page = await context.newPage();
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(1000);

  const password = getRequiredEnv('E2E_FREIGHTER_PASSWORD');

  // Its mnemonic is throwaway — every test imports its own ephemeral account.
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

  // Add and switch to the local quickstart network.
  await page.goto(`chrome-extension://${EXT_ID}/index.html#/manage-network/add-network`);
  await page.waitForTimeout(800);
  await page.fill(SEL.networkNameInput, LOCAL_NETWORK.name);
  await page.fill(SEL.networkHorizonUrlInput, LOCAL_NETWORK.horizonUrl);
  await page.fill(SEL.networkRpcUrlInput, LOCAL_NETWORK.rpcUrl);
  await page.fill(SEL.networkPassphraseInput, LOCAL_NETWORK.passphrase);
  await page.fill(SEL.networkFriendbotUrlInput, LOCAL_NETWORK.friendbotUrl);
  await page.check(SEL.networkAllowHttpCheckbox, { force: true });
  await page.check(SEL.networkSwitchToItCheckbox, { force: true });
  await page.click(SEL.networkFormAddButton);
  await page.waitForTimeout(800);
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  await page.waitForTimeout(800);

  // Sidebar mode — runner.mjs's approval-URL discovery depends on this.
  await page.click(SEL.accountHeaderIconBtn);
  await page.waitForTimeout(300);
  await page.getByText(SEL.sidebarModeText, { exact: true }).first().click({ force: true });
  await page.waitForTimeout(500);

  step('Freighter wallet created, local network active, sidebar mode on');
  await page.close();
}

// ── Verify the profile: import a throwaway ephemeral account and connect ──
async function verifyProfile(context) {
  step('verifying the provisioned profile');
  const appUrl = requireAppUrl();

  const account = createAccount();
  await fund(account);
  const seedPage = await context.newPage();
  await seedPage.goto(appUrl);
  await seedDriverOnboarding(seedPage, account);
  await seedPage.close();

  await importAccount(context, account.secret());

  const page = await context.newPage();
  await connectApp(page, { appUrl, context });

  const wizardVisible = await page.evaluate(
    () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
  );
  if (wizardVisible) {
    throw new Error('verify: onboarding wizard rendered for a seeded ephemeral account');
  }

  await page.click('[data-view="move-funds"]');
  await page.locator('#btn-deposit').waitFor({ state: 'visible', timeout: 15000 });

  step('profile verified: network active, wizard skips for a seeded account, deposit form reachable');
}

async function main() {
  if (VERIFY_ONLY) {
    const context = await launch({ userDataDir: PROFILE_DIR, headless: true });
    try {
      await unlockFreighter(context);
      await verifyProfile(context);
    } finally {
      await context.close();
    }
    return;
  }

  // Builds only — never verifies here, since this exact directory is what
  // gets tar'd next and verification imports a wallet (see --verify above).
  const context = await launch({ userDataDir: PROFILE_DIR, headless: false });
  try {
    await unlockFreighter(context);
    await provisionFreighter(context);
  } finally {
    await context.close();
  }

  step('provisioning complete — run provision.sh to snapshot');
}

main().catch((err) => {
  console.error('provision: FAILED —', scrub(err.message));
  process.exit(1);
});

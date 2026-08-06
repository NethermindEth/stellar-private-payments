#!/usr/bin/env node
// PROBE (step 1.1 of "Disclosure lifecycle, incrementally"): settle,
// empirically, whether one Chromium profile holding two Freighter accounts
// (A and B, both imported by scripts/setup-freighter-profile.mjs /
// scripts/add-account.mjs) can be switched between and drive the app as
// each account's OWN session — no leakage of A's state into B's.
//
// The app's own account-change handling (Wallet.startWatcher() in
// app/js/ui/navigation.js) polls Freighter every 2s via WatchWalletChanges
// and disconnects itself the moment the active address no longer matches
// what it connected with — it does not silently carry A's session over, it
// forces a fresh connect. And since the app's per-address storage
// (disclaimer acceptance, registered public keys, note/encryption key
// derivation — app/js/ui/onboarding-wizard.js) is keyed by address, B's
// first-ever connect goes through the SAME onboarding wizard A went
// through once, including a fresh signMessage approval for its OWN key
// derivation. Reuses src/onboarding.mjs's driveWizard for that.
//
// What this proves, run against the restored snapshot (both accounts
// already imported):
//   (a) after switching to B and reconnecting, the app displays B's own
//       truncated address, not A's
//   (b) B's privacy keys derive on first use via its own signMessage
//       approval (not skipped, not reusing A's)
//   (c) the app's displayed identity is B's throughout — if A's address or
//       keys ever show up while B is active, that is an app-level session
//       leak, reported via `plan deviate`, not papered over here.
//
// Run standalone (unlike tests/, which go through scripts/run-e2e.sh): it
// restores its own fresh profile from the snapshot via prepare-profile.sh
// and cleans up afterward, the same way run-e2e.sh does for a test file.
//
// Usage:
//   set -a; . deployments/testnet/.e2e-accounts.env; set +a
//   APPROVE=auto node e2e-freighter/scripts/probe-multi-account.mjs

import path from 'node:path';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  launch,
  unlockFreighter,
  connectApp,
  switchFreighterAccount,
  waitForFreighterApproval,
  approveOrWatch,
} from '../src/runner.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`probe-multi-account: missing required env var ${name}`);
    process.exit(1);
  }
  return value;
}

const ADDRESS_A = requireEnv('E2E_ACCOUNT_C_ADDRESS');
const ADDRESS_B = requireEnv('E2E_ACCOUNT_D_ADDRESS');

function assert(condition, message) {
  if (!condition) throw new Error(`probe-multi-account: ${message}`);
}

// Freighter renders the address truncated ("GCDVNXYD...6SE75S") — compare
// against a real address by its head+tail, mirroring runner.mjs's own
// truncation-tolerant matching for connectApp()'s return value.
function truncatedMatches(displayed, fullAddress) {
  const head = fullAddress.slice(0, 8);
  const tail = fullAddress.slice(-6);
  return displayed.includes(head) || displayed.includes(tail);
}

async function main() {
  const headless = process.env.HEADFUL !== '1';

  const profileSubdir = execFileSync('bash', [path.join(__dirname, 'prepare-profile.sh')], { encoding: 'utf8' }).trim();
  const userDataDir = path.dirname(profileSubdir);
  const tmpRoot = path.dirname(userDataDir);

  const context = await launch({ userDataDir, headless });
  try {
    await unlockFreighter(context);

    // Account 1 is Freighter's own throwaway generated wallet (scripts/
    // setup-freighter-profile.mjs's "Create new wallet" step, made before A
    // was imported as a second account) — not one of the two accounts this
    // probe cares about. A landed as "Account 2" (first import), B as
    // "Account 3" (scripts/add-account.mjs's later import), discovered
    // empirically since Freighter numbers accounts by creation/import order,
    // not anything this codebase controls. Importing B also made it the
    // active wallet (Freighter auto-selects a freshly imported account), so
    // force a known starting point rather than assuming.
    console.log('[probe-multi-account] forcing starting account to Account 2 (A)...');
    await switchFreighterAccount(context, 'Account 2');

    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());

    const addressA = await connectApp(page, { context });
    console.log(`[probe-multi-account] connected as A: ${addressA}`);
    assert(
      truncatedMatches(addressA, ADDRESS_A),
      `initial connect shows "${addressA}", which doesn't match account A (${ADDRESS_A}) — check the snapshot's default active account`,
    );

    console.log('[probe-multi-account] switching Freighter to account B...');
    await switchFreighterAccount(context, 'Account 3');

    // The app polls every 2s and disconnects itself once it notices the
    // active address changed — give it a beat, then confirm it actually
    // did so rather than assuming.
    await page.waitForTimeout(3000);
    const disconnectedVisible = await page.getByText('Connect Freighter', { exact: true }).isVisible().catch(() => false);
    assert(
      disconnectedVisible,
      'app did not disconnect after the active Freighter account changed — Wallet.startWatcher() should have caught this within 2s',
    );
    console.log('[probe-multi-account] app disconnected itself after the account switch, as expected');

    const addressB = await connectApp(page, { context });
    console.log(`[probe-multi-account] reconnected, app now shows: ${addressB}`);
    assert(
      truncatedMatches(addressB, ADDRESS_B),
      `after switching to B and reconnecting, the app shows "${addressB}" — expected it to match account B (${ADDRESS_B})`,
    );
    assert(
      !truncatedMatches(addressB, ADDRESS_A),
      `after switching to B, the app still shows an address matching A (${ADDRESS_A}) — this is a session leak, report via plan deviate`,
    );

    // B has never connected before: its own onboarding wizard runs fresh
    // (per-address disclaimer/registration/key-derivation gates), including
    // its own signMessage approval for key derivation.
    const wizardVisible = await page.evaluate(
      () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
    );
    assert(wizardVisible, "B's first connect did not raise the onboarding wizard — expected it to derive B's own keys fresh");
    console.log("[probe-multi-account] B's onboarding wizard appeared, as expected for a first-ever connect; driving it...");
    await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: 'probe-multi-account' });

    // Re-read the identity after the wizard, in case any step re-renders it.
    const bodyTextAfterWizard = await page.innerText('body');
    assert(
      !bodyTextAfterWizard.includes(ADDRESS_A.slice(0, 8)),
      "A's address appears in the page body while B is the connected account — session leak, report via plan deviate",
    );

    console.log('[probe-multi-account] OK: switching accounts in one profile shows each account\'s own session, no leakage');
  } finally {
    await context.close();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error('probe-multi-account: FAILED:', err.message);
  process.exit(1);
});

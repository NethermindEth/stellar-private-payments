#!/usr/bin/env node
import '../src/env.mjs';
// Complete the app's onboarding wizard once, headed, against the LIVE
// working profile (e2e-freighter/.chrome-profile — NOT a temp restore).
//
// Why headed: the wizard's step transitions rely on a CSS animation to
// reach their laid-out state, and under --headless=new that animation can
// stall, leaving the current step's buttons at 0x0 (hit at 'registration'
// in the U1 probes, at 'explorer' in a later deviation). Completing it
// headed sidesteps the stall entirely — wizard completion is persisted
// profile state (app/js/ui/onboarding-wizard.js's localStorage flag plus
// storage.setSetting calls), so doing it once and re-snapshotting carries
// the completed state into every future headless run.
//
// Runs unattended: drives every step automatically, including approving
// the real signMessage prompt Freighter raises for key derivation.
//
// The wizard driver itself lives in ../src/onboarding.mjs, shared with
// scripts/probe-multi-account.mjs (a second account's first-ever connect
// goes through the same per-address-gated wizard, even on an already-
// onboarded profile).
//
// Usage:
//   set -a; . deployments/testnet/.e2e-accounts.env; set +a
//   node e2e-freighter/scripts/complete-onboarding.mjs

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  launch,
  unlockFreighter,
  connectApp,
  waitForFreighterApproval,
  approveOrWatch,
} from '../src/runner.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PROFILE_DIR = path.join(REPO_ROOT, 'e2e-freighter', '.chrome-profile');
const APP_URL = process.env.APP_URL || 'https://nethermindeth.github.io/stellar-private-payments/#move-funds';

async function main() {
  const context = await launch({ userDataDir: PROFILE_DIR, headless: false });
  try {
    await unlockFreighter(context);
    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());
    await connectApp(page, { appUrl: APP_URL, context });
    await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag: 'complete-onboarding' });

    const stillVisible = await page.evaluate(
      () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
    );
    if (stillVisible) throw new Error('complete-onboarding: onboarding modal still visible after driving all steps');
    console.log('complete-onboarding: done — onboarding wizard fully completed and persisted');
  } finally {
    await context.close();
  }
}

main().catch((err) => {
  console.error('complete-onboarding: FAILED:', err.message);
  process.exit(1);
});

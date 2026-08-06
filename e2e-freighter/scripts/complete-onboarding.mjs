#!/usr/bin/env node
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PROFILE_DIR = path.join(REPO_ROOT, 'e2e-freighter', '.chrome-profile');
const APP_URL = process.env.APP_URL || 'https://nethermindeth.github.io/stellar-private-payments/#move-funds';

const WIZARD_BUTTON_PRIORITY = [
  // Storage step: "Continue without it" only sets a "prompted" flag, not
  // `persisted` — app/js/ui/onboarding-wizard.js's own gating
  // (`!persisted || !storagePrompted`) means skipping it never stops the
  // step recurring. "Request persistent storage" actually calls
  // navigator.storage.persist() (granted via the runner's launch()-time CDP
  // durableStorage permission), which resolves `persisted = true` for good.
  'Request persistent storage',
  'Use default', // explorer step: keep the default explorer base URL
  // Retention step: "Continue" (ghost) resolves the step WITHOUT saving a
  // bootnode_config setting, so the wizard's `!bootnodeSetting` gate makes
  // it reappear every session forever. "Save retention setup" is the only
  // choice that actually persists.
  'Save retention setup',
  'Register later', // registration step: skip (excluded from the reappear gate)
  'Derive and store keys', // keys step: required, triggers a signMessage approval
  'Continue', // the storage step's own follow-on panel after a successful request
];

async function driveWizard(page, context) {
  for (let step = 0; step < 10; step += 1) {
    // #onboarding-modal is always present in the DOM — the app toggles a
    // "hidden" class (app/index.html:496) rather than removing it. A plain
    // existence check never sees completion; check that class instead.
    const modalHidden = await page.evaluate(
      () => document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true,
    );
    if (modalHidden) {
      console.log(`complete-onboarding: wizard finished after ${step} step(s)`);
      return;
    }
    const readButtons = () =>
      page.$$eval('#onboarding-modal button', (els) =>
        els
          .map((el) => {
            const rect = el.getBoundingClientRect();
            return { text: el.textContent.trim(), zeroRect: rect.width === 0 && rect.height === 0 };
          })
          .filter((b) => b.text),
      );
    let buttons = await readButtons();
    const settleDeadline = Date.now() + 5000;
    while (buttons.length && buttons.every((b) => b.zeroRect) && Date.now() < settleDeadline) {
      await page.waitForTimeout(300);
      buttons = await readButtons();
    }
    if (!buttons.length) throw new Error('complete-onboarding: onboarding modal present but has no labeled buttons');
    if (buttons.every((b) => b.zeroRect)) {
      throw new Error(
        `complete-onboarding: buttons still laid out at 0x0 after a 5s settle wait, even headed ` +
          `(${buttons.map((b) => b.text).join(', ')}) — the headed fix did not hold; this needs a fresh deviation.`,
      );
    }

    const choice = WIZARD_BUTTON_PRIORITY.find((text) => buttons.some((b) => b.text === text));
    if (!choice) throw new Error(`complete-onboarding: no recognized button among [${buttons.map((b) => b.text).join(', ')}]`);

    console.log(`complete-onboarding: step ${step}, clicking "${choice}"`);
    await page.getByText(choice, { exact: true }).first().click({ force: true });

    if (choice === 'Derive and store keys') {
      const approvalPage = await waitForFreighterApproval(context, 'signMessage', { timeoutMs: 30000 }).catch(() => null);
      if (approvalPage) await approveOrWatch(context, 'signMessage', { timeoutMs: 30000 });
    }

    await page.waitForTimeout(1000);
  }
  throw new Error('complete-onboarding: wizard did not finish within 10 steps');
}

async function main() {
  const context = await launch({ userDataDir: PROFILE_DIR, headless: false });
  try {
    await unlockFreighter(context);
    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());
    await connectApp(page, { appUrl: APP_URL, context });
    await driveWizard(page, context);

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

#!/usr/bin/env node
// Verify that a freshly restored profile snapshot reaches the app's Move
// Funds deposit form with NO onboarding wizard modal — i.e. that the headed
// completion run (scripts/complete-onboarding.mjs) actually got baked into
// the snapshot, and every future headless run skips the wizard entirely.
//
// MUST run against a restored copy (scripts/prepare-profile.sh), never the
// live working profile — this is what future headless test runs actually
// see.
//
// Usage:
//   set -a; . deployments/testnet/.e2e-accounts.env; set +a
//   APPROVE=auto node e2e-freighter/scripts/verify-onboarded.mjs

import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, unlockFreighter, connectApp } from '../src/runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_URL = process.env.APP_URL || 'https://nethermindeth.github.io/stellar-private-payments/#move-funds';

async function main() {
  const profileSubdir = execFileSync('bash', [path.join(__dirname, 'prepare-profile.sh')], { encoding: 'utf8' }).trim();
  const userDataDir = path.dirname(profileSubdir);

  const context = await launch({ userDataDir, headless: true });
  try {
    await unlockFreighter(context);
    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());
    await connectApp(page, { appUrl: APP_URL, context });

    const wizardVisible = await page.evaluate(
      () => !(document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true),
    );
    if (wizardVisible) {
      throw new Error('verify-onboarded: onboarding wizard rendered on a restored snapshot — completion did not persist into the snapshot');
    }

    const depositBtn = page.locator('#btn-deposit');
    await depositBtn.waitFor({ state: 'visible', timeout: 15000 });

    console.log('verify-onboarded: OK — no onboarding wizard, Move Funds deposit form is reachable');
  } finally {
    await context.close();
  }
}

main().catch((err) => {
  console.error('verify-onboarded: FAILED:', err.message);
  process.exit(1);
});

#!/usr/bin/env node
// Runner core for driving the app against a real Freighter extension.
//
// Freighter approvals appear as ordinary CDP page targets at
// chrome-extension://<freighter-id>/index.html#/<route>?<payload> where
// <route> is "grant-access" (connect), "sign-message" (key derivation), or
// "sign-transaction". Headed + sidebar mode prefixes that with
// "?mode=sidebar" before the hash; headless does not. Discovery here always
// matches on the hash route alone, browser-wide across every open target
// (approvals can land in a separate window), and never on Freighter's CSS
// classes — only visible button text (Confirm / Cancel / Connect / Sign).

import { createLogger } from './logger.mjs';
import { requireAppUrl } from './env.mjs';
import { waitForCondition } from './waits.mjs';
import {
  APP_RUNTIME_READY_TIMEOUT_MS,
  isBootnodeConsentVisible,
  isOnboardingWizardVisible,
  readAppLifecycle,
  waitForWalletRuntimeReady,
} from './appState.mjs';
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  approveOrWatch,
  rejectInFreighter,
  unlockFreighter,
  waitForAnyFreighterApproval,
  waitForFreighterApproval,
} from './wallet.mjs';

export {
  approveOrWatch,
  rejectInFreighter,
  switchFreighterAccount,
  unlockFreighter,
  waitForAnyFreighterApproval,
  waitForFreighterApproval,
} from './wallet.mjs';

export {
  APP_RUNTIME_READY_TIMEOUT_MS,
  isBootnodeConsentVisible,
  isOnboardingWizardVisible,
  readAppLifecycle,
  waitForWalletRuntimeReady,
} from './appState.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const EXT_PATH = path.resolve(PKG_ROOT, 'vendor', 'freighter');
const CHROMIUM_PATH = process.env.E2E_CHROMIUM_PATH || '/usr/bin/chromium';
const log = createLogger('runner');

export async function launch({ userDataDir, headless = true, video = false } = {}) {
  if (!userDataDir) throw new Error('launch: userDataDir is required');
  const contextOptions = {
    headless,
    executablePath: CHROMIUM_PATH,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-first-run',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      ...(process.env.CHROMIUM_FLAGS ? process.env.CHROMIUM_FLAGS.split(/\s+/) : []),
    ],
    // The onboarding flow requests notification permission. Grant it before
    // navigation because automated clicks cannot satisfy this browser prompt.
    permissions: ['notifications'],
  };
  if (video) {
    contextOptions.recordVideo = { dir: path.join(PKG_ROOT, 'test-results', 'videos') };
  }
  const context = await chromium.launchPersistentContext(userDataDir, contextOptions);

  // Persistent-storage permission is session-scoped and must be granted via
  // CDP for each browser context.
  try {
    const appOrigin = new URL(requireAppUrl()).origin;
    const page = context.pages()[0] || (await context.newPage());
    const cdp = await context.newCDPSession(page);
    await cdp.send('Browser.grantPermissions', { origin: appOrigin, permissions: ['durableStorage'] });
  } catch (err) {
    log.warn('launch: could not grant durableStorage permission:', err.message);
  }

  return context;
}

// Opens the app, connects Freighter if not already connected, and asserts
// the connection succeeded.
//
// The app displays a truncated address. Connection is asserted from the
// wallet button's visibility; the returned address is for logging only.
export async function connectApp(page, { appUrl = requireAppUrl(), context } = {}) {
  if (!context) throw new Error('connectApp: context is required (needed to watch for the connect approval)');
  await page.goto(appUrl);
  await page.waitForLoadState('domcontentloaded');
  await waitForCondition({
    operation: 'app:load',
    timeoutMs: 10_000,
    intervalMs: 100,
    observe: async () => ({
      readyState: await page.evaluate(() => document.readyState),
      dashboardVisible: await page.getByTestId('view-dashboard').isVisible().catch(() => false),
    }),
    isReady: ({ readyState, dashboardVisible }) => readyState === 'complete' && dashboardVisible,
  });

  // The button remains in the DOM while connected; visibility distinguishes
  // the disconnected state. Use its stable identity rather than button text.
  const connectBtn = page.locator('#wallet-btn');
  let clickedConnect = false;
  if (await connectBtn.isVisible().catch(() => false)) {
    try {
      // Automatic connection may hide the button between the visibility check
      // and the click.
      await connectBtn.click({ timeout: 5_000 });
      clickedConnect = true;
    } catch (err) {
      if (await connectBtn.isVisible().catch(() => false)) throw err;
    }
  }
  if (clickedConnect) {
    // The approval target is optional.
    try {
      await approveOrWatch(context, 'connect', { timeoutMs: 8_000 });
    } catch {
      // no popup within the short window — assume it auto-approved.
    }
  }

  // A missing-history check can require explicit bootnode consent before the
  // onboarding wizard is shown. Treat both modals as an intentional paused
  // connect state instead of timing out while `Wallet.connect()` is blocked.
  await waitForCondition({
    operation: 'app:connect-or-setup-modal',
    timeoutMs: APP_RUNTIME_READY_TIMEOUT_MS,
    intervalMs: 100,
    observe: () => readAppLifecycle(page),
    isReady: ({ walletState, onboardingVisible, bootnodeConsentVisible }) =>
      walletState === 'ready' || onboardingVisible || bootnodeConsentVisible,
  });

  if (await isBootnodeConsentVisible(page)) {
    log.info('connectApp: bootnode consent is open — accepting the configured default');
    await page.getByRole('button', { name: 'Use bootnode', exact: true }).click();
    await waitForCondition({
      operation: 'app:bootnode-consent-close',
      timeoutMs: 10_000,
      intervalMs: 100,
      observe: () => isBootnodeConsentVisible(page),
      isReady: (visible) => !visible,
    });

    // The app continues into onboarding only after it persists the consent.
    await waitForCondition({
      operation: 'app:bootnode-consent-continue',
      timeoutMs: APP_RUNTIME_READY_TIMEOUT_MS,
      intervalMs: 100,
      observe: () => readAppLifecycle(page),
      isReady: ({ walletState, onboardingVisible }) => walletState === 'ready' || onboardingVisible,
    });
  }

  // The caller completes onboarding before continuing with the scenario.
  if (await isOnboardingWizardVisible(page)) {
    log.info('connectApp: onboarding wizard is open — returning for the caller to drive it');
  } else {
    // An address can render before the runtime and selected pool are usable.
    await waitForWalletRuntimeReady(page, { timeoutMs: APP_RUNTIME_READY_TIMEOUT_MS });

    if (await connectBtn.isVisible().catch(() => false)) {
      throw new Error('connectApp: "Connect Freighter" is still shown after connecting — connection did not succeed');
    }
  }

  const bodyText = await page.innerText('body');
  const match = bodyText.match(/G[A-Z2-7.…]{5,20}[A-Z2-7]{4,10}/);
  return match ? match[0] : '(connected, address text not found)';
}

// ---------------------------------------------------------------------------
// CLI entry point, invoked by scripts/run-e2e.sh
// ---------------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);
  const smoke = args.includes('--smoke');

  const userDataDir = process.env.E2E_CHROME_USER_DATA_DIR;
  if (!userDataDir) throw new Error('runner: E2E_CHROME_USER_DATA_DIR not set (run via scripts/run-e2e.sh)');

  const headless = process.env.HEADFUL !== '1';
  const video = !!process.env.CI;

  const context = await launch({ userDataDir, headless, video });
  try {
    await unlockFreighter(context);

    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());
    const address = await connectApp(page, { context });
    log.info('connected:', address);

    if (smoke) {
      log.info('smoke: reached connected state, done');
      return;
    }

    const testFile = args.find((a) => !a.startsWith('--'));
    if (!testFile) throw new Error('runner: no test file given and --smoke not set');
    log.info('test:', testFile);
    const testModule = await import(path.resolve(testFile));
    await testModule.run({
      context,
      page,
      connectApp,
      waitForFreighterApproval,
      waitForAnyFreighterApproval,
      approveOrWatch,
      rejectInFreighter,
    });
  } finally {
    await context.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(async (err) => {
    log.error('FAILED:', err.stack || err.message);
    process.exit(1);
  });
}

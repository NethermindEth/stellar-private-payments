#!/usr/bin/env node
// Runner core for driving the app against a real Freighter extension.
//
// Built directly on the U1 probe findings (the sidebar/headless approval
// surface investigation): approvals appear as ordinary CDP page targets at
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
    // The app's onboarding wizard offers a notification permission prompt
    // (retention step) via Notification.requestPermission(); a scripted,
    // non-genuine-gesture click never resolves that in real Chrome, which
    // stalls the step's resolve() forever. Pre-granting it here is the
    // supported Playwright equivalent of a human clicking "Allow" — not a
    // workaround of app behavior, just letting an automated run get past a
    // permission prompt with no human present to click it.
    permissions: ['notifications'],
  };
  if (video) {
    contextOptions.recordVideo = { dir: path.join(PKG_ROOT, 'test-results', 'videos') };
  }
  const context = await chromium.launchPersistentContext(userDataDir, contextOptions);

  // durableStorage cannot be baked into the profile snapshot: Chrome's
    // Permissions API grants are per-browser-session state, not profile data
    // that carries over in a user-data-dir tar.gz. Playwright's permission
    // model doesn't expose 'persistent-storage', so it goes through raw CDP
    // (Browser.grantPermissions), same effect as a human clicking "Allow".
    // Without this, navigator.storage.persist() never resolves true in a
    // scripted session, stalling the wizard's storage step forever.
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
// The app renders the connected address TRUNCATED (e.g. "GCDVNXYD...6SE75S"),
// not the full 56-char form, so this doesn't pattern-match a full address —
// it asserts the "Connect Freighter" button is gone (the app only shows it
// while disconnected) and returns whatever truncated address text is shown,
// for logging only.
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

  // The button stays in the DOM (class "hidden") even once connected, so
  // .count() alone always finds it — visibility, not presence, is what
  // distinguishes disconnected from connected here.
  // Use the app's stable identity rather than text.  The button remains in
  // the DOM while connected and can be rerendered while the wallet bootstrap
  // finishes, so a text locator can resolve a transiently hidden element.
  const connectBtn = page.locator('#wallet-btn');
  let clickedConnect = false;
  if (await connectBtn.isVisible().catch(() => false)) {
    try {
      // The app may complete an automatic connection between the visibility
      // probe and the click.  Keep this timeout short and accept that race
      // when the button has become hidden by the time click() returns.
      await connectBtn.click({ timeout: 5_000 });
      clickedConnect = true;
    } catch (err) {
      if (await connectBtn.isVisible().catch(() => false)) throw err;
    }
  }
  if (clickedConnect) {
    // Freighter auto-approves a previously-granted origin without a popup,
    // so a grant-access target may never appear; only handle it if it does.
    try {
      await approveOrWatch(context, 'connect', { timeoutMs: 8_000 });
    } catch {
      // no popup within the short window — assume it auto-approved.
    }
  }

  // First connect on a fresh profile surfaces the app's own disclaimer
  // modal (unrelated to Freighter) before the connected address renders.
  const disclaimerBtn = page.getByText('Accept disclaimer', { exact: true });
  const walletState = page.locator('body');
  await waitForCondition({
    operation: 'app:connect-or-disclaimer',
    timeoutMs: 30_000,
    intervalMs: 100,
    observe: async () => ({
      walletState: await walletState.getAttribute('data-wallet-state').catch(() => 'unknown'),
      disclaimerVisible: await disclaimerBtn.isVisible().catch(() => false),
    }),
    isReady: ({ walletState: state, disclaimerVisible }) => state === 'ready' || disclaimerVisible,
  });
  if (await disclaimerBtn.isVisible().catch(() => false)) {
    await disclaimerBtn.click();
    await waitForCondition({
      operation: 'app:disclaimer',
      timeoutMs: 10_000,
      intervalMs: 100,
      observe: async () => ({ visible: await disclaimerBtn.isVisible().catch(() => false) }),
      isReady: ({ visible }) => !visible,
    });
  }

  // A connected address is rendered before the runtime and selected pool are
  // usable. Wait for the app's production lifecycle marker so the first
  // operation cannot race the post-connect initialization.
  await waitForCondition({
    operation: 'app:wallet-runtime-ready',
    timeoutMs: 30_000,
    intervalMs: 100,
    observe: async () => ({
      walletState: await walletState.getAttribute('data-wallet-state').catch(() => 'unknown'),
      connectButtonVisible: await connectBtn.isVisible().catch(() => false),
    }),
    isReady: ({ walletState: state }) => state === 'ready',
  });

  if (await connectBtn.isVisible().catch(() => false)) {
    throw new Error('connectApp: "Connect Freighter" is still shown after connecting — connection did not succeed');
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
    log.error('FAILED:', err.message);
    process.exit(1);
  });
}

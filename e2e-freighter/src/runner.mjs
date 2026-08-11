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

import { createLogger, enableFileLogging } from './logger.mjs';
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const EXT_PATH = path.resolve(PKG_ROOT, 'vendor', 'freighter');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';
const CHROMIUM_PATH = process.env.E2E_CHROMIUM_PATH || '/usr/bin/chromium';
const log = createLogger('runner');
const DEFAULT_APP_URL = 'https://nethermindeth.github.io/stellar-private-payments/#move-funds';

// ---------------------------------------------------------------------------
// Freighter selectors — the maintenance surface. Discovered by manually
// driving the extension; re-verify against vendor/freighter/manifest.json's
// version if these stop matching.
// ---------------------------------------------------------------------------
const SEL = {
  unlockPasswordInput: '#password-input',
  unlockButtonText: 'Unlock',
};

// App-side text, not Freighter's — the button the app itself renders to
// start a connection.
const APP_CONNECT_BUTTON_TEXT = 'Connect Freighter';

// Approval hash routes proven reachable as ordinary page targets in U1
// (connect/signMessage/signTransaction), plus sign-auth-entry (same family,
// route confirmed present in the vendored extension build).
const APPROVAL_ROUTES = {
  connect: 'grant-access',
  signMessage: 'sign-message',
  signTransaction: 'sign-transaction',
  signAuthEntry: 'sign-auth-entry',
};

const APPROVE_BUTTON_TEXT = {
  connect: 'Connect',
  signMessage: 'Confirm',
  signTransaction: 'Confirm',
  signAuthEntry: 'Confirm',
};

function isFreighterApprovalUrl(url, kind) {
  if (!url.startsWith(`chrome-extension://${EXT_ID}/`)) return false;
  const route = APPROVAL_ROUTES[kind];
  if (!route) throw new Error(`isFreighterApprovalUrl: unknown approval kind '${kind}'`);
  // Match "#/<route>" wherever it appears in the URL — covers both the
  // headless form (.../index.html#/<route>?...) and the headed sidebar form
  // (.../index.html?mode=sidebar#/<route>?...).
  return url.includes(`#/${route}`);
}

export async function launch({ userDataDir, headless = true, video = false } = {}) {
  if (!userDataDir) throw new Error('launch: userDataDir is required');
  const contextOptions = {
    headless,
    executablePath: CHROMIUM_PATH,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-first-run',
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

  // Same reasoning as the 'notifications' grant above, for the wizard's
  // storage step: navigator.storage.persist() never resolves true for a
  // scripted session without this — there is no Playwright-level
  // 'persistent-storage' permission name, so this goes through the raw CDP
  // permission Playwright doesn't expose (Browser.grantPermissions
  // "durableStorage"), same effect as a human clicking "Allow".
  try {
    const appOrigin = new URL(process.env.APP_URL || DEFAULT_APP_URL).origin;
    const page = context.pages()[0] || (await context.newPage());
    const cdp = await context.newCDPSession(page);
    await cdp.send('Browser.grantPermissions', { origin: appOrigin, permissions: ['durableStorage'] });
  } catch (err) {
    log.warn('launch: could not grant durableStorage permission:', err.message);
  }

  return context;
}

async function extensionHomePage(context) {
  await new Promise((r) => setTimeout(r, 800));
  const existing = context.pages().find((p) => p.url().startsWith(`chrome-extension://${EXT_ID}/`));
  const page = existing || (await context.newPage());
  // Bare index.html (no hash) lets Freighter's router pick the correct
  // screen for the current account state; "#/welcome" always renders the
  // create/import choice regardless of state (same fix as U1's profile
  // setup script needed).
  await page.goto(`chrome-extension://${EXT_ID}/index.html`);
  return page;
}

export async function unlockFreighter(context, password = process.env.E2E_FREIGHTER_PASSWORD) {
  if (!password) throw new Error('unlockFreighter: E2E_FREIGHTER_PASSWORD not set');
  const page = await extensionHomePage(context);
  await page.waitForTimeout(1000);
  if (!page.url().includes('unlock-account')) return page; // already unlocked
  await page.fill(SEL.unlockPasswordInput, password);
  await page.getByText(SEL.unlockButtonText, { exact: true }).click();
  await page.waitForTimeout(1000);
  return page;
}

// Switch Freighter's active wallet, e.g. between multiple imported accounts
// in the same profile ("Account 1", "Account 2", ...) — the generic labels
// Freighter assigns on creation/import, not anything app- or user-defined.
// Selectors: the current account's name (data-testid="account-view-account-
// name") opens the account list; each row in that list is a WalletRow whose
// name text (class "detail-name") both displays the account and, per its own
// onClick, selects it when clicked — so clicking the target row's name text
// is the switch action itself, no separate "confirm" step.
export async function switchFreighterAccount(context, accountName) {
  const page = await extensionHomePage(context);
  await page.waitForTimeout(500);

  await page.click('[data-testid="account-view-account-name"]', { force: true });
  await page.waitForTimeout(600);

  const row = page.locator('.detail-name', { hasText: accountName }).first();
  await row.waitFor({ state: 'visible', timeout: 10000 });
  await row.click({ force: true });
  await page.waitForTimeout(800);

  return page;
}

// Surface-agnostic finder: scans every open target browser-wide (never
// assumes one window) and matches on the approval's hash route regardless
// of whether "?mode=sidebar" precedes it.
export async function waitForFreighterApproval(context, kind, { timeoutMs = 30000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      if (isFreighterApprovalUrl(page.url(), kind)) return page;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`waitForFreighterApproval: no '${kind}' approval target appeared within ${timeoutMs}ms`);
}

// For flows that can raise more than one kind of approval in an order the
// caller doesn't control in advance (e.g. deposit may prompt signAuthEntry
// and/or signTransaction) — scans for the first of any listed kind.
export async function waitForAnyFreighterApproval(context, kinds, { timeoutMs = 30000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      for (const kind of kinds) {
        if (isFreighterApprovalUrl(page.url(), kind)) return { page, kind };
      }
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`waitForAnyFreighterApproval: none of [${kinds.join(', ')}] appeared within ${timeoutMs}ms`);
}

async function clickByText(page, text) {
  try {
    await page.getByText(text, { exact: true }).first().click({ force: true });
  } catch (err) {
    // A multi-transaction flow (e.g. deposit raising several sequential
    // signTransaction prompts) can have the popup we found already closing
    // by the time we act on it — Freighter auto-advances/closes it once its
    // own state resolves. Treat "already gone" as already-handled rather
    // than a hard failure; anything else still propagates.
    if (page.isClosed() || /closed/i.test(err.message)) return;
    throw err;
  }
}

// APPROVE=auto clicks the text-matched approve button. APPROVE=human is a
// first-class preset (the demo path, not an afterthought): it never touches
// the popup, just waits for the human to act and for the target to close.
export async function approveOrWatch(context, kind, { timeoutMs = 30000 } = {}) {
  const page = await waitForFreighterApproval(context, kind, { timeoutMs });
  const mode = (process.env.APPROVE || 'auto').toLowerCase();

  if (mode === 'human') {
    log.info(`APPROVE=human: waiting for you to act on the '${kind}' approval (Confirm/Cancel)...`);
    await Promise.race([
      new Promise((resolve) => page.once('close', resolve)),
      new Promise((r) => setTimeout(r, timeoutMs)),
    ]);
    return;
  }

  await clickByText(page, APPROVE_BUTTON_TEXT[kind] || 'Confirm');
}

export async function rejectInFreighter(context, kind, { timeoutMs = 30000 } = {}) {
  const page = await waitForFreighterApproval(context, kind, { timeoutMs });
  await clickByText(page, 'Cancel');
}

// Opens the app, connects Freighter if not already connected, and asserts
// the connection succeeded.
//
// The app renders the connected address TRUNCATED (e.g. "GCDVNXYD...6SE75S"),
// not the full 56-char form, so this doesn't pattern-match a full address —
// it asserts the "Connect Freighter" button is gone (the app only shows it
// while disconnected) and returns whatever truncated address text is shown,
// for logging only.
export async function connectApp(page, { appUrl = process.env.APP_URL || DEFAULT_APP_URL, context } = {}) {
  if (!context) throw new Error('connectApp: context is required (needed to watch for the connect approval)');
  await page.goto(appUrl);
  await page.waitForTimeout(1500);

  // The button stays in the DOM (class "hidden") even once connected, so
  // .count() alone always finds it — visibility, not presence, is what
  // distinguishes disconnected from connected here.
  const connectBtn = page.getByText(APP_CONNECT_BUTTON_TEXT, { exact: true });
  if (await connectBtn.isVisible().catch(() => false)) {
    await connectBtn.click();
    // Freighter auto-approves a previously-granted origin without a popup,
    // so a grant-access target may never appear; only handle it if it does.
    try {
      await approveOrWatch(context, 'connect', { timeoutMs: 8000 });
    } catch {
      // no popup within the short window — assume it auto-approved.
    }
    await page.waitForTimeout(1500);
  }

  // First connect on a fresh profile surfaces the app's own disclaimer
  // modal (unrelated to Freighter) before the connected address renders.
  const disclaimerBtn = page.getByText('Accept disclaimer', { exact: true });
  if (await disclaimerBtn.isVisible().catch(() => false)) {
    await disclaimerBtn.click();
    await page.waitForTimeout(1000);
  }

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

  enableFileLogging(path.join(PKG_ROOT, 'test-results', 'e2e-run.log'));

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

    // Print a formatted failure block with recent log context
    const { getRecentLines } = await import('./logger.mjs');
    const sep = '-'.repeat(58);
    console.error(`\n${sep}\n  FAILURE\n${sep}`);
    console.error('  error:  ', err.message);
    console.error('  recent log:');
    for (const line of getRecentLines(15)) {
      console.error(`    ${line}`);
    }
    console.error(`${sep}\n`);

    process.exit(1);
  });
}

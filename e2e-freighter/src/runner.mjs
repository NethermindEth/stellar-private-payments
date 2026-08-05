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

import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const EXT_PATH = path.resolve(PKG_ROOT, 'vendor', 'freighter');
const EXT_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';
const CHROMIUM_PATH = process.env.E2E_CHROMIUM_PATH || '/usr/bin/chromium';
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

// Approval hash routes proven reachable as ordinary page targets in U1.
const APPROVAL_ROUTES = {
  connect: 'grant-access',
  signMessage: 'sign-message',
  signTransaction: 'sign-transaction',
};

const APPROVE_BUTTON_TEXT = {
  connect: 'Connect',
  signMessage: 'Confirm',
  signTransaction: 'Confirm',
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
  };
  if (video) {
    contextOptions.recordVideo = { dir: path.join(PKG_ROOT, 'test-results', 'videos') };
  }
  return chromium.launchPersistentContext(userDataDir, contextOptions);
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

async function clickByText(page, text) {
  await page.getByText(text, { exact: true }).first().click({ force: true });
}

// APPROVE=auto clicks the text-matched approve button. APPROVE=human is a
// first-class preset (the demo path, not an afterthought): it never touches
// the popup, just waits for the human to act and for the target to close.
export async function approveOrWatch(context, kind, { timeoutMs = 30000 } = {}) {
  const page = await waitForFreighterApproval(context, kind, { timeoutMs });
  const mode = (process.env.APPROVE || 'auto').toLowerCase();

  if (mode === 'human') {
    console.log(`[runner] APPROVE=human: waiting for you to act on the '${kind}' approval (Confirm/Cancel)...`);
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

  const context = await launch({ userDataDir, headless, video });
  try {
    await unlockFreighter(context);

    const page = context.pages().find((p) => p.url().startsWith('https://')) || (await context.newPage());
    const address = await connectApp(page, { context });
    console.log(`[runner] connected: ${address}`);

    if (smoke) {
      console.log('[runner] smoke: reached connected state, done');
      return;
    }

    const testFile = args.find((a) => !a.startsWith('--'));
    if (!testFile) throw new Error('runner: no test file given and --smoke not set');
    const testModule = await import(path.resolve(testFile));
    await testModule.run({
      context,
      page,
      connectApp,
      waitForFreighterApproval,
      approveOrWatch,
      rejectInFreighter,
    });
  } finally {
    await context.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('[runner] FAILED:', err.message);
    process.exit(1);
  });
}

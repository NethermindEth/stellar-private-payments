// Freighter extension operations. This module owns approval discovery and
// interaction; runner.mjs remains responsible for browser-context lifecycle.

import { createLogger } from './logger.mjs';
import { WaitTimeoutError, waitForCondition } from './waits.mjs';

export const FREIGHTER_EXTENSION_ID = 'bcacfldlkkdogcmkkibnjlakofdplcbk';

const log = createLogger('wallet');
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

export function isFreighterApprovalUrl(url, kind) {
  if (!url.startsWith(`chrome-extension://${FREIGHTER_EXTENSION_ID}/`)) return false;
  const route = APPROVAL_ROUTES[kind];
  if (!route) throw new Error(`isFreighterApprovalUrl: unknown approval kind '${kind}'`);
  return url.includes(`#/${route}`);
}

function isFreighterExtensionPage(url) {
  return url.startsWith(`chrome-extension://${FREIGHTER_EXTENSION_ID}/`);
}

function extensionPages(context) {
  return context.pages()
    .map((page) => page.url())
    .filter(isFreighterExtensionPage);
}

async function extensionHomePage(context) {
  const existing = context.pages().find((page) => isFreighterExtensionPage(page.url()));
  const page = existing || (await context.newPage());
  await page.goto(`chrome-extension://${FREIGHTER_EXTENSION_ID}/index.html`);
  return page;
}

export async function unlockFreighter(context, password = process.env.E2E_FREIGHTER_PASSWORD) {
  if (!password) throw new Error('unlockFreighter: E2E_FREIGHTER_PASSWORD not set');
  const page = await extensionHomePage(context);
  // The extension router may redirect from bare index.html to its account
  // screen after navigation resolves. Wait for a routed URL when it appears;
  // an already-unlocked profile can legitimately stay at the bare URL.
  await page.waitForURL(/#\//, { timeout: 5_000 }).catch(() => {});
  const unlockInput = page.locator('#password-input');
  if (!(await unlockInput.isVisible().catch(() => false))) return page;

  await unlockInput.fill(password);
  await page.getByText('Unlock', { exact: true }).click();
  await waitForCondition({
    operation: 'freighter:unlock',
    timeoutMs: 15_000,
    observe: async () => ({ url: page.url(), unlockVisible: await unlockInput.isVisible().catch(() => false) }),
    isReady: ({ unlockVisible }) => !unlockVisible,
  }).catch((error) => {
    throw new Error(
      `unlockFreighter: still on the unlock screen after entering E2E_FREIGHTER_PASSWORD; ` +
      `the snapshot and .e2e-accounts.env must come from the same provisioning run. ${error.message}`,
    );
  });
  return page;
}

export async function switchFreighterAccount(context, accountName) {
  const page = await extensionHomePage(context);
  const accountButton = page.locator('[data-testid="account-view-account-name"]');
  await accountButton.waitFor({ state: 'visible', timeout: 10_000 });
  await accountButton.click({ force: true });

  const row = page.locator('.detail-name', { hasText: accountName }).first();
  await row.waitFor({ state: 'visible', timeout: 10_000 });
  await row.click({ force: true });
  return page;
}

async function pageShowsApprovalButton(page, buttonText) {
  if (page.isClosed?.()) return false;
  return page.getByRole('button', { name: buttonText, exact: true }).isVisible().catch(() => false);
}

export async function findFreighterApproval(context, kinds) {
  for (const page of context.pages()) {
    const url = page.url();
    for (const kind of kinds) {
      if (isFreighterApprovalUrl(url, kind)) return { page, kind };
    }
    if (!isFreighterExtensionPage(url)) continue;
    for (const kind of kinds) {
      const buttonText = APPROVE_BUTTON_TEXT[kind];
      if (buttonText && await pageShowsApprovalButton(page, buttonText)) return { page, kind };
    }
  }
  return null;
}

async function waitForApproval(context, kinds, {
  timeoutMs = 30_000,
  intervalMs = 300,
  waitOptions = {},
} = {}) {
  const result = await waitForCondition({
    operation: `freighter-approval:${kinds.join('|')}`,
    timeoutMs,
    intervalMs,
    ...waitOptions,
    observe: async () => ({
      approval: await findFreighterApproval(context, kinds),
      extensionPages: extensionPages(context),
      requestedKinds: kinds,
    }),
    isReady: ({ approval }) => Boolean(approval),
  });
  return result.value.approval;
}

export async function waitForFreighterApproval(context, kind, options) {
  return (await waitForApproval(context, [kind], options)).page;
}

export function waitForAnyFreighterApproval(context, kinds, options) {
  return waitForApproval(context, kinds, options);
}

/** Prove a pre-signing operation did not open any Freighter approval. */
export async function expectNoFreighterApproval(context, kinds, options) {
  try {
    const approval = await waitForAnyFreighterApproval(context, kinds, options);
    throw new Error(`unexpected Freighter approval: ${approval.kind}`);
  } catch (error) {
    if (error instanceof WaitTimeoutError) return true;
    throw error;
  }
}

async function clickByText(page, text) {
  try {
    await page.getByText(text, { exact: true }).first().click({ force: true });
    return { pageClosed: false };
  } catch (error) {
    if (page.isClosed?.() || /closed/i.test(error.message)) return { pageClosed: true };
    throw error;
  }
}

async function waitForApprovalResolution(page, kind, { timeoutMs = 5_000 } = {}) {
  const buttonText = APPROVE_BUTTON_TEXT[kind] || 'Confirm';
  await waitForCondition({
    operation: `freighter-approval-resolve:${kind}`,
    timeoutMs,
    intervalMs: 100,
    observe: async () => ({
      closed: page.isClosed?.() || false,
      url: page.url(),
      buttonVisible: await pageShowsApprovalButton(page, buttonText),
    }),
    isReady: ({ closed, url, buttonVisible }) => (
      closed || !isFreighterApprovalUrl(url, kind) || !buttonVisible
    ),
  });
}

export function waitForPageClose(page, {
  timeoutMs = 30_000,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (page.isClosed?.()) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => {
      if (timer !== undefined) clearTimer(timer);
      page.off('close', onClose);
    };
    const onClose = () => {
      cleanup();
      resolve();
    };
    page.on('close', onClose);
    timer = setTimer(() => {
      cleanup();
      reject(new Error(`[wallet] approval page did not close within ${timeoutMs}ms`));
    }, timeoutMs);
  });
}

export async function approveOrWatch(context, kind, {
  timeoutMs = 30_000,
  label = kind,
  mode = (process.env.APPROVE || 'auto').toLowerCase(),
  waitOptions,
  pageCloseOptions,
} = {}) {
  const startedAt = Date.now();
  const page = await waitForFreighterApproval(context, kind, { timeoutMs, waitOptions });
  log.info(`APPROVE: '${label}' approval page found after ${Date.now() - startedAt}ms`);

  if (mode === 'human') {
    log.info(`APPROVE=human: waiting for you to act on the '${label}' approval (Confirm/Cancel)...`);
    await waitForPageClose(page, { timeoutMs, ...pageCloseOptions });
    return { kind, mode, pageClosed: true };
  }

  const buttonText = APPROVE_BUTTON_TEXT[kind] || 'Confirm';
  try {
    await page.getByText(buttonText, { exact: true }).first().waitFor({ state: 'visible', timeout: 10_000 });
  } catch (error) {
    if (page.isClosed?.() || /closed/i.test(error.message)) return { kind, mode, pageClosed: true };
    throw error;
  }
  const result = await clickByText(page, buttonText);
  if (!result.pageClosed) await waitForApprovalResolution(page, kind);
  log.info(`APPROVE: '${label}' Confirm ${result.pageClosed ? 'already closed' : 'clicked'} after ${Date.now() - startedAt}ms`);
  return { kind, mode, ...result };
}

export async function rejectInFreighter(context, kind, options = {}) {
  const page = await waitForFreighterApproval(context, kind, options);
  try {
    await page.getByText('Cancel', { exact: true }).first().waitFor({ state: 'visible', timeout: 10_000 });
  } catch (error) {
    if (page.isClosed?.() || /closed/i.test(error.message)) return { kind, pageClosed: true };
    throw error;
  }
  return { kind, ...(await clickByText(page, 'Cancel')) };
}

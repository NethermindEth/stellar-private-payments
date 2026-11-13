// App lifecycle state shared by the runner and onboarding driver.
// `body[data-wallet-state]` transitions from `disconnected` to `connecting`
// to `ready`. Onboarding must complete before the runtime can become ready.

import { waitForCondition } from './waits.mjs';

// Includes runtime and selected-pool initialization.
export const APP_RUNTIME_READY_TIMEOUT_MS = 60_000;

const WALLET_STATE_ATTRIBUTE = 'data-wallet-state';
const ACCESS_STATE_ATTRIBUTE = 'data-access-state';
export const ACCESS_STATES = ['welcome', 'returning', 'connecting', 'locked', 'ready'];
const ONBOARDING_MODAL_SELECTOR = '#onboarding-modal';
const BOOTNODE_CONSENT_MODAL_SELECTOR = '#bootnode-consent-modal';

async function readWalletState(page) {
  return (await page.locator('body').getAttribute(WALLET_STATE_ATTRIBUTE).catch(() => null)) || 'unknown';
}

/**
 * The wizard is a `<dialog>` that stays in the DOM while closed, so presence
 * proves nothing — visibility is the signal. Throws once the page is gone, so a
 * crash never reads as a closed wizard.
 */
export async function isOnboardingWizardVisible(page) {
  return page.locator(ONBOARDING_MODAL_SELECTOR).isVisible();
}

// A missing-history check happens before `runOnboardingWizard()`. The app
// deliberately blocks there until the user accepts a bootnode, so callers
// waiting only for the onboarding modal would otherwise time out with the
// lifecycle pinned at `connecting`.
export async function isBootnodeConsentVisible(page) {
  return page.locator(BOOTNODE_CONSENT_MODAL_SELECTOR).isVisible().catch(() => false);
}

export async function readAppLifecycle(page) {
  const [walletState, onboardingVisible, bootnodeConsentVisible] = await Promise.all([
    readWalletState(page),
    isOnboardingWizardVisible(page).catch(() => false),
    isBootnodeConsentVisible(page),
  ]);
  return { walletState, onboardingVisible, bootnodeConsentVisible };
}

/**
 * Wait until the app's runtime and selected pool are usable.
 *
 * An open onboarding wizard prevents the lifecycle from reaching `ready`.
 */
export async function waitForWalletRuntimeReady(page, {
  timeoutMs = APP_RUNTIME_READY_TIMEOUT_MS,
  intervalMs = 100,
  waitOptions = {},
} = {}) {
  const result = await waitForCondition({
    operation: 'app:wallet-runtime-ready',
    timeoutMs,
    intervalMs,
    ...waitOptions,
    observe: async () => {
      const lifecycle = await readAppLifecycle(page);
      if (lifecycle.walletState === 'connecting' && lifecycle.onboardingVisible) {
        throw new Error(
          'the onboarding wizard is open, so the wallet lifecycle cannot reach "ready": ' +
          'Wallet.connect() awaits runOnboardingWizard(). Drive the wizard first ' +
          '(driveWizard from src/onboarding.mjs), then wait for runtime readiness.',
        );
      }
      return lifecycle;
    },
    isReady: ({ walletState }) => walletState === 'ready',
    ignoreError: () => false,
  });
  return result.value;
}

/**
 * What the app asks of the user before its data views open, from
 * `body[data-access-state]`: `welcome` (first visit), `returning` (a store
 * exists but no wallet is connected), `connecting`, `locked` (wallet connected,
 * storage locked) or `ready` (storage open). `unknown` until the app sets it.
 */
export async function readAccessState(page) {
  return (await page.locator('body').getAttribute(ACCESS_STATE_ATTRIBUTE).catch(() => null)) || 'unknown';
}

/** Wait until the app shell has loaded and published its access state. */
export async function waitForAppShell(page, { timeoutMs = 10_000, waitOptions = {} } = {}) {
  return waitForCondition({
    operation: 'app:load', timeoutMs, intervalMs: 100, ...waitOptions,
    observe: async () => ({
      readyState: await page.evaluate(() => document.readyState),
      accessState: await readAccessState(page),
    }),
    isReady: ({ readyState, accessState }) => readyState === 'complete' && ACCESS_STATES.includes(accessState),
  });
}

/** Wait for a specific access state, e.g. `locked` after a lock reload. */
export async function waitForAccessState(page, expected, { timeoutMs = 30_000, waitOptions = {} } = {}) {
  const wanted = [expected].flat();
  return waitForCondition({
    operation: `app:access-${wanted.join('|')}`, timeoutMs, intervalMs: 100, ...waitOptions,
    observe: () => readAccessState(page),
    isReady: state => wanted.includes(state),
  });
}

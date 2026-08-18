// App lifecycle state shared by the runner and the onboarding driver.
//
// `body[data-wallet-state]` is the production connect lifecycle marker:
// 'disconnected' → 'connecting' → 'ready'. Reaching 'ready' requires
// Wallet.connect() to get past its own `await runOnboardingWizard(...)`
// (app/js/ui/navigation.js), so on a profile that still needs onboarding the
// marker cannot advance until something drives the wizard modal. Both
// observations live here so connectApp() and driveWizard() agree on what
// "usable" means instead of each waiting for the other.

import { waitForCondition } from './waits.mjs';

// A fresh headed CI profile may still be initializing the WASM runtime and the
// selected pool after Freighter has supplied the address. Keep a cold-start
// margin here; ordinary app navigation and approval waits remain shorter.
export const APP_RUNTIME_READY_TIMEOUT_MS = 60_000;

export const WALLET_STATE_ATTRIBUTE = 'data-wallet-state';
export const ONBOARDING_MODAL_SELECTOR = '#onboarding-modal';

export async function readWalletState(page) {
  return (await page.locator('body').getAttribute(WALLET_STATE_ATTRIBUTE).catch(() => null)) || 'unknown';
}

/**
 * The wizard modal stays in the DOM and is toggled with a `hidden` class, so
 * presence proves nothing — visibility is the signal.
 */
export async function isOnboardingWizardVisible(page) {
  return page.locator(ONBOARDING_MODAL_SELECTOR).isVisible().catch(() => false);
}

export async function readAppLifecycle(page) {
  const [walletState, onboardingVisible] = await Promise.all([
    readWalletState(page),
    isOnboardingWizardVisible(page),
  ]);
  return { walletState, onboardingVisible };
}

/**
 * Wait until the app's runtime and selected pool are usable.
 *
 * An open onboarding wizard is a dead end here, not a slow path: the marker
 * is blocked behind the wizard's own promise, so this fails immediately with
 * the actionable cause instead of burning the whole deadline.
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

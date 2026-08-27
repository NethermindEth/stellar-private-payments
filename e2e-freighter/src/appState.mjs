// App lifecycle state shared by the runner and onboarding driver.
// `body[data-wallet-state]` transitions from `disconnected` to `connecting`
// to `ready`. Onboarding must complete before the runtime can become ready.

import { waitForCondition } from './waits.mjs';

// Includes runtime and selected-pool initialization.
export const APP_RUNTIME_READY_TIMEOUT_MS = 60_000;

export const WALLET_STATE_ATTRIBUTE = 'data-wallet-state';
export const ONBOARDING_MODAL_SELECTOR = '#onboarding-modal';
export const BOOTNODE_CONSENT_MODAL_SELECTOR = '#bootnode-consent-modal';

// Settings-drawer elements the app writes `App.state.wallet.address` and
// `App.state.keys.{notePublicKey,encryptionPublicKey}` into verbatim, every
// time it renders (see app/js/ui/navigation.js renderSettingsDrawer) —
// unlike `#wallet-text`, which holds `Utils.shortAddress(...)`, a truncated
// display value. The build bundles the app's ES modules into one non-module
// file with nothing exposed on `window` (trunk/esbuild), so there is no live
// `App.state` object a test can reach directly; these three elements are the
// most direct proxy for it that is actually reachable from the page.
const WALLET_ADDRESS_SELECTOR = '#settings-wallet-address';
const NOTE_PUBLIC_KEY_SELECTOR = '#settings-note-key';
const ENCRYPTION_PUBLIC_KEY_SELECTOR = '#settings-enc-key';
const NOT_CONNECTED_PLACEHOLDER = 'Not connected';
const NO_KEY_PLACEHOLDER = '—';

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
    isOnboardingWizardVisible(page),
    isBootnodeConsentVisible(page),
  ]);
  return { walletState, onboardingVisible, bootnodeConsentVisible };
}

/**
 * Which address the app's currently-derived privacy keys (note + encryption
 * public keys) are bound to, from observable app state rather than by
 * scraping a truncated address out of arbitrary page text.
 *
 * Returns `{ address, notePublicKey, encryptionPublicKey }`, each `null`
 * when the corresponding element still shows its unset placeholder (e.g.
 * before a wallet is connected, or right after `Wallet.disconnect()` resets
 * `App.state.keys`).
 */
export async function readKeyBinding(page) {
  const readField = async (selector, placeholder) => {
    const raw = await page.locator(selector).textContent().catch(() => null);
    const value = raw?.trim();
    return value && value !== placeholder ? value : null;
  };
  const [address, notePublicKey, encryptionPublicKey] = await Promise.all([
    readField(WALLET_ADDRESS_SELECTOR, NOT_CONNECTED_PLACEHOLDER),
    readField(NOTE_PUBLIC_KEY_SELECTOR, NO_KEY_PLACEHOLDER),
    readField(ENCRYPTION_PUBLIC_KEY_SELECTOR, NO_KEY_PLACEHOLDER),
  ]);
  return { address, notePublicKey, encryptionPublicKey };
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

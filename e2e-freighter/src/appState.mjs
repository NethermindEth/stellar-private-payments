// App lifecycle state shared by the runner and onboarding driver.
// `body[data-wallet-state]` transitions from `disconnected` to `connecting`
// to `locked` (public indexing) or `ready` (private account access).
// Onboarding must complete before the private runtime can become ready.

import { waitForCondition } from './waits.mjs';

// Includes runtime and selected-pool initialization.
export const APP_RUNTIME_READY_TIMEOUT_MS = 60_000;

export const WALLET_STATE_ATTRIBUTE = 'data-wallet-state';
export const ONBOARDING_MODAL_SELECTOR = '#onboarding-modal';
export const BOOTNODE_CONSENT_MODAL_SELECTOR = '#bootnode-consent-modal';
export const STORAGE_PASSWORD_DIALOG_SELECTOR = '[data-testid="storage-password-dialog"]';

// Private scenarios explicitly open local data, then use this password to
// create, migrate or unlock it. Public connection must not ask for a password.
export const APP_PASSWORD = process.env.E2E_APP_PASSWORD || 'e2e local data password';

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

export async function isStoragePasswordVisible(page) {
  return page.locator(STORAGE_PASSWORD_DIALOG_SELECTOR).isVisible().catch(() => false);
}

export async function readAppLifecycle(page) {
  const [walletState, onboardingVisible, bootnodeConsentVisible, storagePasswordVisible] = await Promise.all([
    readWalletState(page),
    isOnboardingWizardVisible(page),
    isBootnodeConsentVisible(page),
    isStoragePasswordVisible(page),
  ]);
  return { walletState, onboardingVisible, bootnodeConsentVisible, storagePasswordVisible };
}

/**
 * Answer the local-data password dialog with {@link APP_PASSWORD}, whichever
 * of its modes is open, and wait until the app accepts it. Unlocking derives
 * the key and may first encrypt an earlier database, so this can take a while.
 */
export async function answerStoragePassword(page) {
  const dialog = page.locator(STORAGE_PASSWORD_DIALOG_SELECTOR);
  const mode = await dialog.getAttribute('data-mode');
  await page.getByTestId('storage-password-input').fill(APP_PASSWORD);
  if (mode !== 'locked') {
    await page.getByTestId('storage-password-confirm').fill(APP_PASSWORD);
  }
  await page.getByTestId('storage-password-submit').click();
  const { value } = await waitForCondition({
    operation: `storage:password-${mode}`,
    timeoutMs: 120_000,
    intervalMs: 200,
    // Existing wallet scenarios use password-only storage. Dismiss the
    // optional Freighter offer before waiting for the dialog to close.
    observe: async () => {
      const skip = page.getByTestId('storage-freighter-skip');
      if (await skip.isVisible()) await skip.click();
      const skipPasskey = page.getByTestId('storage-passkey-skip');
      if (await skipPasskey.isVisible()) await skipPasskey.click();
      return page.evaluate((selector) => {
        const node = document.querySelector(selector);
        return {
          visible: Boolean(node?.checkVisibility()),
          error: node?.querySelector('[data-testid="storage-password-error"]')?.textContent ?? '',
        };
      }, STORAGE_PASSWORD_DIALOG_SELECTOR);
    },
    isReady: ({ visible, error }) => !visible || Boolean(error?.trim()),
  });
  if (value.visible) {
    throw new Error(`the local-data password was refused (${mode}): ${value.error.trim()}`);
  }
  return mode;
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

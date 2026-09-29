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
export const STORAGE_WALLET_DIALOG_SELECTOR = '[data-testid="storage-wallet-dialog"]';

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

export async function isStorageWalletVisible(page) {
  return page.locator(STORAGE_WALLET_DIALOG_SELECTOR).isVisible().catch(() => false);
}

export async function readAppLifecycle(page) {
  const [walletState, onboardingVisible, bootnodeConsentVisible, storageWalletVisible] = await Promise.all([
    readWalletState(page),
    isOnboardingWizardVisible(page),
    isBootnodeConsentVisible(page),
    isStorageWalletVisible(page),
  ]);
  return { walletState, onboardingVisible, bootnodeConsentVisible, storageWalletVisible };
}

/** Approve only the wallet messages requested by the local storage dialog. */
export async function answerStorageWallet(page, context) {
  const { approveOrWatch } = await import('./wallet.mjs');
  const dialog = page.locator(STORAGE_WALLET_DIALOG_SELECTOR);
  const mode = await dialog.getAttribute('data-mode');
  const approvals = ['new', 'unencrypted'].includes(mode) ? 2 : 1;
  await page.getByTestId('storage-wallet-submit').click();
  for (let i = 0; i < approvals; i++) {
    await approveOrWatch(context, 'signMessage', { timeoutMs: 30_000 });
  }
  const { value } = await waitForCondition({
    operation: 'storage:wallet-unlock', timeoutMs: 120_000, intervalMs: 100,
    observe: async () => ({
      visible: await dialog.isVisible(),
      error: await page.getByTestId('storage-wallet-error').textContent().catch(() => ''),
    }),
    isReady: ({ visible, error }) => !visible || Boolean(error?.trim()),
  });
  if (value.visible) throw Error(`Wallet storage failed: ${value.error}`);
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

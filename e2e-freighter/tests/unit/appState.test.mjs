import assert from 'node:assert/strict';
import test from 'node:test';

import { readAppLifecycle, waitForWalletRuntimeReady } from '../../src/appState.mjs';

// Fake page over the two observations appState makes: body's lifecycle
// attribute and the onboarding modal's visibility. Each entry is one poll.
function fakePage(snapshots) {
  let index = 0;
  const next = () => snapshots[Math.min(index, snapshots.length - 1)];
  return {
    advance() { index += 1; },
    locator(selector) {
      if (selector === 'body') {
        return {
          async getAttribute(name) {
            assert.equal(name, 'data-wallet-state');
            const snapshot = next();
            index += 1;
            return snapshot.walletState;
          },
        };
      }
      if (selector === '#bootnode-consent-modal') {
        return { async isVisible() { return next().bootnodeConsentVisible || false; } };
      }
      assert.equal(selector, '#onboarding-modal');
      return { async isVisible() { return next().onboardingVisible; } };
    },
  };
}

const instantWait = () => {
  let now = 0;
  return { now: () => now, sleep: async (ms) => { now += ms; } };
};

test('readAppLifecycle reports both observations, defaulting a missing marker', async () => {
  assert.deepEqual(
    await readAppLifecycle(fakePage([{ walletState: null, onboardingVisible: false }])),
    { walletState: 'unknown', onboardingVisible: false, bootnodeConsentVisible: false },
  );
});

test('readAppLifecycle reports the pre-onboarding bootnode consent', async () => {
  assert.deepEqual(
    await readAppLifecycle(fakePage([{
      walletState: 'connecting',
      onboardingVisible: false,
      bootnodeConsentVisible: true,
    }])),
    { walletState: 'connecting', onboardingVisible: false, bootnodeConsentVisible: true },
  );
});

test('waitForWalletRuntimeReady resolves once the lifecycle marker reaches ready', async () => {
  const page = fakePage([
    { walletState: 'connecting', onboardingVisible: false },
    { walletState: 'ready', onboardingVisible: false },
  ]);

  const lifecycle = await waitForWalletRuntimeReady(page, {
    timeoutMs: 1_000,
    waitOptions: instantWait(),
  });

  assert.equal(lifecycle.walletState, 'ready');
});

test('an open onboarding wizard fails fast instead of burning the whole deadline', async () => {
  // Wallet.connect() awaits runOnboardingWizard(), so readiness cannot be
  // reached while the modal remains open.
  const page = fakePage([{ walletState: 'connecting', onboardingVisible: true }]);

  await assert.rejects(
    waitForWalletRuntimeReady(page, { timeoutMs: 60_000, waitOptions: instantWait() }),
    (error) => {
      assert.match(error.message, /onboarding wizard is open/);
      assert.match(error.message, /driveWizard/);
      assert.ok(!(error.name === 'WaitTimeoutError'), 'should not be reported as a timeout');
      return true;
    },
  );
});

test('a wizard that closes while waiting still reaches ready', async () => {
  const page = fakePage([
    { walletState: 'connecting', onboardingVisible: false },
    { walletState: 'ready', onboardingVisible: false },
  ]);

  const lifecycle = await waitForWalletRuntimeReady(page, {
    timeoutMs: 1_000,
    waitOptions: instantWait(),
  });

  assert.equal(lifecycle.walletState, 'ready');
});

test('a lifecycle that never advances still reports a timeout with its last state', async () => {
  const page = fakePage([{ walletState: 'connecting', onboardingVisible: false }]);

  await assert.rejects(
    waitForWalletRuntimeReady(page, { timeoutMs: 300, waitOptions: instantWait() }),
    (error) => {
      assert.equal(error.name, 'WaitTimeoutError');
      assert.deepEqual(error.lastObservedState, {
        walletState: 'connecting', onboardingVisible: false, bootnodeConsentVisible: false,
      });
      return true;
    },
  );
});

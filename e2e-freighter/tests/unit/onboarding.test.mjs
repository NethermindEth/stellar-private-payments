import assert from 'node:assert/strict';
import test from 'node:test';

import { driveWizard } from '../../src/onboarding.mjs';

// A synthetic wizard: each entry in `stepsButtons` is the single recognized
// button shown at that step (all drawn from WIZARD_BUTTON_PRIORITY so
// driveWizard accepts them); once every entry has been clicked the modal is
// "closed" and the post-wizard lifecycle markers read as ready. This models
// exactly the surface driveWizard touches: the modal's hidden class (via
// evaluate), its button list (via $$eval), button clicks (via getByText),
// and the lifecycle waitForWalletRuntimeReady reads afterward (via locator).
function fakeWizardPage(stepsButtons, { walletState = 'ready' } = {}) {
  let stepIndex = 0;
  const clicks = [];
  const lifecycleReads = [];
  const finished = () => stepIndex >= stepsButtons.length;
  return {
    clicks,
    lifecycleReads,
    async evaluate() { return finished(); },
    async $$eval(selector) {
      assert.equal(selector, '#onboarding-modal button');
      return (stepsButtons[stepIndex] || []).map((text) => ({ text, zeroRect: false }));
    },
    getByText(text, options) {
      assert.deepEqual(options, { exact: true });
      return {
        first: () => ({
          async click() {
            clicks.push(text);
            stepIndex += 1;
          },
        }),
      };
    },
    locator(selector) {
      if (selector === 'body') {
        return {
          async getAttribute() {
            lifecycleReads.push(walletState);
            return walletState;
          },
        };
      }
      if (selector === '#onboarding-modal') return { async isVisible() { return !finished(); } };
      if (selector === '#bootnode-consent-modal') return { async isVisible() { return false; } };
      throw new Error(`fakeWizardPage: unexpected selector '${selector}'`);
    },
  };
}

// Neither is exercised by these tests: none of the synthetic wizards include
// "Derive and store keys", the only step that touches them.
const noopApprovals = {
  waitForFreighterApproval: async () => { throw new Error('waitForFreighterApproval: not expected'); },
  approveOrWatch: async () => { throw new Error('approveOrWatch: not expected'); },
};

test('driveWizard clicks the recognized button at each step and finishes when the modal closes', async () => {
  const page = fakeWizardPage([['Accept disclaimer'], ['Register later']]);

  await driveWizard(page, {}, { ...noopApprovals, logTag: 'test' });

  assert.deepEqual(page.clicks, ['Accept disclaimer', 'Register later']);
});

test('onStep fires once per step, before that step\'s click, without altering the click sequence', async () => {
  const page = fakeWizardPage([['Accept disclaimer'], ['Use default'], ['Register later']]);
  const calls = [];

  await driveWizard(page, {}, {
    ...noopApprovals,
    logTag: 'test',
    onStep: async ({ step, choice, buttons }) => {
      calls.push({ step, choice, clicksSoFar: page.clicks.length });
      assert.deepEqual(buttons.map((b) => b.text), [choice]);
    },
  });

  assert.deepEqual(page.clicks, ['Accept disclaimer', 'Use default', 'Register later']);
  assert.deepEqual(calls, [
    { step: 0, choice: 'Accept disclaimer', clicksSoFar: 0 },
    { step: 1, choice: 'Use default', clicksSoFar: 1 },
    { step: 2, choice: 'Register later', clicksSoFar: 2 },
  ]);
});

test('omitting onStep leaves the click sequence byte-for-byte identical to passing a no-op one', async () => {
  const steps = [['Accept disclaimer'], ['Save retention setup'], ['Register later']];

  const withoutHook = fakeWizardPage(steps);
  await driveWizard(withoutHook, {}, { ...noopApprovals, logTag: 'test' });

  const withNoopHook = fakeWizardPage(steps);
  await driveWizard(withNoopHook, {}, { ...noopApprovals, logTag: 'test', onStep: async () => {} });

  assert.deepEqual(withoutHook.clicks, withNoopHook.clicks);
});

test('a step with no recognized button throws before onStep runs', async () => {
  const page = fakeWizardPage([['Some Unrecognized Button']]);
  let onStepCalled = false;

  await assert.rejects(
    driveWizard(page, {}, {
      ...noopApprovals,
      logTag: 'test',
      onStep: async () => { onStepCalled = true; },
    }),
    /no recognized button/,
  );
  assert.equal(onStepCalled, false);
});

test('onStep can drive a side effect (e.g. switching the active Freighter account) mid-wizard', async () => {
  const page = fakeWizardPage([['Accept disclaimer'], ['Register later']]);
  const sideEffects = [];

  await driveWizard(page, {}, {
    ...noopApprovals,
    logTag: 'test',
    onStep: async ({ choice }) => {
      if (choice === 'Register later') sideEffects.push('switched-account');
    },
  });

  assert.deepEqual(sideEffects, ['switched-account']);
  assert.deepEqual(page.clicks, ['Accept disclaimer', 'Register later']);
});

test('by default driveWizard waits for the post-onboarding runtime lifecycle', async () => {
  const page = fakeWizardPage([['Accept disclaimer']]);

  await driveWizard(page, {}, { ...noopApprovals, logTag: 'test' });

  assert.deepEqual(page.clicks, ['Accept disclaimer']);
  assert.ok(
    page.lifecycleReads.length > 0,
    'expected driveWizard to read body[data-wallet-state] while waiting for runtime readiness',
  );
});

test('a step that triggers multiple signMessage approvals gets every one of them approved', async () => {
    // Opening an SDK session for an address with no keys yet can prompt twice
    // in sequence (session auth, then privacy-key derivation) — driveWizard
    // must keep approving until Freighter stops showing new ones.
    const page = fakeWizardPage([['Accept disclaimer'], ['Register later']]);
    const approvals = ['first approval page', 'second approval page', null];
    const approved = [];

    await driveWizard(page, {}, {
        logTag: 'test',
        waitForFreighterApproval: async () => {
            const next = approvals.shift();
            if (next === null) return null;
            return next;
        },
        approveOrWatch: async (context, kind) => { approved.push(kind); },
    });

    assert.deepEqual(approved, ['signMessage', 'signMessage']);
    assert.deepEqual(page.clicks, ['Accept disclaimer', 'Register later']);
});

test('waitForRuntimeReady:false returns as soon as the wizard closes, without waiting on the lifecycle', async () => {
  // `disconnected` is the state the app lands in when onboarding finishes
  // while the active wallet account differs from the connected one: the
  // default wait would spin here until it timed out.
  const page = fakeWizardPage([['Accept disclaimer']], { walletState: 'disconnected' });

  await driveWizard(page, {}, { ...noopApprovals, logTag: 'test', waitForRuntimeReady: false });

  assert.deepEqual(page.clicks, ['Accept disclaimer']);
  assert.deepEqual(page.lifecycleReads, []);
});

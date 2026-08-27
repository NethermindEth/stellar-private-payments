// Drive the app onboarding wizard to completion. Several wizard gates are
// keyed by wallet address, so each account can require onboarding.

import { createLogger } from './logger.mjs';
import { waitForCondition } from './waits.mjs';
import { waitForWalletRuntimeReady } from './appState.mjs';

const WIZARD_BUTTON_PRIORITY = [
  'Accept disclaimer', // first step; must be acknowledged before anything else
  // Storage step: "Continue without it" only sets a "prompted" flag, not
  // `persisted` — app/js/ui/onboarding-wizard.js's own gating
  // (`!persisted || !storagePrompted`) means skipping it never stops the
  // step recurring. "Request persistent storage" actually calls
  // navigator.storage.persist() (granted via the runner's launch()-time CDP
  // durableStorage permission), which resolves `persisted = true` for good.
  // This is app-level (not per-address) so a second account on the same
  // profile should already see it satisfied.
  'Request persistent storage',
  'Use default', // explorer step: keep the default explorer base URL
  // Retention step: "Continue" (ghost) resolves the step WITHOUT saving a
  // bootnode_config setting, so the wizard's `!bootnodeSetting` gate makes
  // it reappear every session forever. "Save retention setup" is the only
  // choice that actually persists.
  'Save retention setup',
  'Register later', // registration step: skip (excluded from the reappear gate)
  'Derive and store keys', // keys step: required, triggers a signMessage approval
  'Continue', // the storage step's own follow-on panel after a successful request
];

export async function driveWizard(page, context, {
  waitForFreighterApproval,
  approveOrWatch,
  logTag = 'onboarding',
  // Optional mid-wizard hook: called with `{ step, choice, buttons }` right
  // before the chosen button is clicked, so a test can act on the app or
  // the Freighter extension at a specific, named point in the wizard (e.g.
  // switch the active Freighter account right before "Derive and store
  // keys" is clicked) without driveWizard itself knowing why. Every
  // existing caller omits it, so `onStep` stays `undefined` and this is a
  // no-op — default behaviour is unchanged.
  onStep,
  // Whether to wait for the app's post-onboarding runtime readiness before
  // returning. Defaults to true, which is what every scenario that goes on
  // to transact needs. A test that deliberately leaves the app in a state it
  // is expected NOT to settle into `ready` from — e.g. finishing onboarding
  // while the active Freighter account differs from the one the app
  // connected as, which makes the app's own account watcher disconnect
  // within one poll tick — must opt out, or it races the disconnect and
  // fails with a readiness timeout instead of its own assertion.
  waitForRuntimeReady = true,
}) {
  const log = createLogger(`${logTag}/wizard`);
  for (let step = 0; step < 10; step += 1) {
    // The modal remains in the DOM and may appear after asynchronous storage
    // checks, so visibility is checked after a short settle window.
    const modalHidden = async () => page.evaluate(
      () => document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true,
    );
    if (await modalHidden()) {
      if (step === 0) {
        await waitForCondition({
          operation: 'onboarding:appear',
          timeoutMs: 5000,
          intervalMs: 100,
          observe: async () => ({ hidden: await modalHidden() }),
          isReady: ({ hidden }) => !hidden,
        }).catch(() => {});
      }
      if (await modalHidden()) {
        log.debug('wizard finished after', step, 'step(s)');
        if (!waitForRuntimeReady) {
          log.debug('skipping the runtime-readiness wait at the caller\'s request');
          return;
        }
        // Wait until account and pool initialization complete.
        const lifecycle = await waitForWalletRuntimeReady(page);
        log.debug('wallet runtime ready:', lifecycle.walletState);
        return;
      }
    }
    const readButtons = () =>
      page.$$eval('#onboarding-modal button', (els) =>
        els
          .map((el) => {
            const rect = el.getBoundingClientRect();
            return { text: el.textContent.trim(), zeroRect: rect.width === 0 && rect.height === 0 };
          })
          .filter((b) => b.text),
      );
    let buttons = await readButtons();
    await waitForCondition({
      operation: 'onboarding:layout',
      timeoutMs: 5000,
      intervalMs: 100,
      observe: async () => {
        buttons = await readButtons();
        return { buttons };
      },
      isReady: ({ buttons: observed }) => observed.length > 0 && observed.some((button) => !button.zeroRect),
    });
    if (!buttons.length) throw new Error(`${logTag}: onboarding modal present but has no labeled buttons`);
    if (buttons.every((b) => b.zeroRect)) {
      throw new Error(
        `${logTag}: buttons still laid out at 0x0 after a 5s settle wait: ` +
          `(${buttons.map((b) => b.text).join(', ')})`,
      );
    }

    const choice = WIZARD_BUTTON_PRIORITY.find((text) => buttons.some((b) => b.text === text));
    if (!choice) throw new Error(`${logTag}: no recognized button among [${buttons.map((b) => b.text).join(', ')}]`);

    const previousButtonText = buttons.map((button) => button.text).join('|');
    if (onStep) await onStep({ step, choice, buttons });
    log.debug('step', step, 'clicking', choice);
    await page.getByText(choice, { exact: true }).first().click({ force: true });

    if (choice === 'Derive and store keys') {
      const approvalPage = await waitForFreighterApproval(context, 'signMessage', { timeoutMs: 30000 }).catch(() => null);
      if (approvalPage) await approveOrWatch(context, 'signMessage', { timeoutMs: 30000 });
    }

    await waitForCondition({
      operation: 'onboarding:step-settle',
      timeoutMs: 5000,
      intervalMs: 100,
      observe: async () => ({
        hidden: await modalHidden(),
        buttonText: (await readButtons()).map((button) => button.text).join('|'),
      }),
      isReady: ({ hidden, buttonText }) => hidden || buttonText !== previousButtonText,
    });
  }
  throw new Error(`${logTag}: wizard did not finish within 10 steps`);
}

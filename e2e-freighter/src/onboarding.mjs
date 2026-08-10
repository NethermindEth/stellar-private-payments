// Shared "drive the app's onboarding wizard to completion" machinery.
// Extracted from scripts/complete-onboarding.mjs (originally written to
// onboard account A once against the live profile) so scripts/probe-
// multi-account.mjs can reuse it for account B's first-ever connect — the
// wizard's per-address gates (disclaimer, registration, key derivation all
// keyed by address in app/js/ui/onboarding-wizard.js) mean a second account
// goes through it fresh even on an already-onboarded profile.

const WIZARD_BUTTON_PRIORITY = [
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

export async function driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag = 'onboarding' }) {
  for (let step = 0; step < 10; step += 1) {
    // #onboarding-modal is always present in the DOM — the app toggles a
    // "hidden" class rather than removing it. A plain existence check never
    // sees completion; check that class instead.
    //
    // The app's startOnboarding runs async storage checks before deciding to
    // show the wizard, so on first load the modal can be hidden for a short
    // window and then appear. Don't treat the initial hidden state as
    // "finished" until the app has had time to settle.
    const modalHidden = async () => page.evaluate(
      () => document.getElementById('onboarding-modal')?.classList.contains('hidden') ?? true,
    );
    if (await modalHidden()) {
      if (step === 0) {
        const settleDeadline = Date.now() + 5000;
        while (Date.now() < settleDeadline) {
          await page.waitForTimeout(300);
          if (!await modalHidden()) break;
        }
      }
      if (await modalHidden()) {
        console.log(`[${logTag}] wizard finished after ${step} step(s)`);
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
    const settleDeadline = Date.now() + 5000;
    while (buttons.length && buttons.every((b) => b.zeroRect) && Date.now() < settleDeadline) {
      await page.waitForTimeout(300);
      buttons = await readButtons();
    }
    if (!buttons.length) throw new Error(`${logTag}: onboarding modal present but has no labeled buttons`);
    if (buttons.every((b) => b.zeroRect)) {
      throw new Error(
        `${logTag}: buttons still laid out at 0x0 after a 5s settle wait, even headed ` +
          `(${buttons.map((b) => b.text).join(', ')}) — the headed fix did not hold; this needs a fresh deviation.`,
      );
    }

    const choice = WIZARD_BUTTON_PRIORITY.find((text) => buttons.some((b) => b.text === text));
    if (!choice) throw new Error(`${logTag}: no recognized button among [${buttons.map((b) => b.text).join(', ')}]`);

    console.log(`[${logTag}] step ${step}, clicking "${choice}"`);
    await page.getByText(choice, { exact: true }).first().click({ force: true });

    if (choice === 'Derive and store keys') {
      const approvalPage = await waitForFreighterApproval(context, 'signMessage', { timeoutMs: 30000 }).catch(() => null);
      if (approvalPage) await approveOrWatch(context, 'signMessage', { timeoutMs: 30000 });
    }

    await page.waitForTimeout(1000);
  }
  throw new Error(`${logTag}: wizard did not finish within 10 steps`);
}

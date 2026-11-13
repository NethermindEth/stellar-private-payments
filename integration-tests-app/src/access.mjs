// Assertions over the app's access states (see appState.mjs readAccessState).

import { assert } from './assert.mjs';
import { waitForCondition } from './waits.mjs';
import { readAccessState, waitForAppShell } from './appState.mjs';

const DATA_VIEWS = ['dashboard', 'move-funds', 'advanced'];

/**
 * Before storage opens, every data view shows the access card instead of a
 * blank page, the account button offers exactly `action`, and there is no
 * lock control.
 */
export async function assertPendingAccess(page, { action }) {
  const state = await readAccessState(page);
  const accountBtn = page.locator('#wallet-btn');
  assert(await accountBtn.isVisible(), `${state}: the account button is hidden`);
  assert(await accountBtn.isEnabled(), `${state}: the account button is disabled`);
  const shown = await accountBtn.getAttribute('data-access-action');
  assert(shown === action, `${state}: the account button offers "${shown}", expected "${action}"`);
  assert(!(await page.getByTestId('storage-lock-btn').isVisible()), `${state}: a lock/unlock control competes with the account button`);

  for (const view of DATA_VIEWS) {
    await page.getByTestId(`nav-${view}`).click();
    await waitForCondition({
      operation: `access:${view}`,
      timeoutMs: 5_000,
      intervalMs: 100,
      observe: async () => ({
        current: await page.getByTestId(`nav-${view}`).getAttribute('aria-current'),
        card: await page.getByTestId('access-card').isVisible(),
        label: (await page.getByTestId('access-view-label').textContent().catch(() => '') || '').trim(),
        panel: await page.getByTestId(`view-${view}`).isVisible(),
      }),
      isReady: ({ current, card, label, panel }) => current === 'page' && card && label.length > 0 && !panel,
    });
    const cta = page.getByTestId('access-card-action');
    assert(await cta.getAttribute('data-access-action') === action, `${state}/${view}: the card's action differs from the header's`);
  }
}

/** Lock storage from the header and wait for the reload to settle. */
export async function lockApp(page) {
  await Promise.all([
    page.waitForEvent('load', { timeout: 30_000 }),
    page.getByTestId('storage-lock-btn').click(),
  ]);
  await waitForAppShell(page);
}

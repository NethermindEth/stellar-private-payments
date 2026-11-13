// Reloading, locking and coming back. With the wallet still remembered, a
// plain reload or a reload after locking reconnects the wallet but opens no
// unlock dialog by itself; it offers only Unlock. After disconnecting, it
// greets a returning user with one Connect action that also unlocks.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { readAccessState, waitForAccessState, waitForAppShell } from '../src/appState.mjs';
import { assertPendingAccess, lockApp } from '../src/access.mjs';

const log = createLogger('15-lock-and-return');

async function assertReady(page, label) {
  const state = await readAccessState(page);
  assert(state === 'ready', `${label}: access state is "${state}"`);
  assert(await page.getByTestId('view-dashboard').isVisible(), `${label}: Overview is hidden`);
}

export async function run({ page, connectApp }) {
  await assertReady(page, 'after connecting');

  // A plain reload waits for the user instead of prompting for a signature.
  await page.reload();
  await waitForAppShell(page);
  await waitForAccessState(page, 'locked');
  assert(!(await page.getByTestId('storage-account-continue').isVisible()),
    'the unlock dialog opened on reload without a click');
  await assertPendingAccess(page, { action: 'unlock' });
  await connectApp(page);
  await assertReady(page, 'after unlocking a reloaded page');

  // The note owner stays remembered, so the reload reconnects the wallet but not storage.
  await lockApp(page);
  await waitForAccessState(page, 'locked');
  await assertPendingAccess(page, { action: 'unlock' });
  await connectApp(page);
  await assertReady(page, 'after unlocking');

  // Disconnecting forgets the owner; storage stays open until it is locked.
  await page.locator('#open-settings-btn').click();
  await page.locator('#wallet-disconnect-btn').click();
  await waitForAccessState(page, 'ready');
  assert(await page.locator('#wallet-btn').getAttribute('data-access-action') === 'connect',
    'disconnecting with open storage does not offer Connect');

  await lockApp(page);
  await waitForAccessState(page, 'returning');
  await assertPendingAccess(page, { action: 'connect' });
  await connectApp(page);
  await assertReady(page, 'after reconnecting');

  log.info('OK: locked and returning states each offer one action');
}

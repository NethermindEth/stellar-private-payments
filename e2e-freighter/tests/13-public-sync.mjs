import { assert } from '../src/assert.mjs';
import { answerStorageWallet } from '../src/appState.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { waitForCondition } from '../src/waits.mjs';

export const connectionOptions = { privateAccess: false };

let failedStartup = false;
let navigations = 0;
const browserErrors = [];
export async function prepare({ page, context }) {
  // The restored extension snapshot can contain pre-upgrade app credentials.
  // This scenario tests fresh wallet-only setup; legacy preservation is covered
  // by the isolated storage suite. Clear only this disposable profile's app origin.
  const cdp = await context.newCDPSession(page);
  await cdp.send('Storage.clearDataForOrigin', {
    origin: new URL(process.env.APP_URL).origin, storageTypes: 'all',
  });
  await cdp.detach();
  page.on('domcontentloaded', () => { navigations++; });
  page.on('pageerror', error => browserErrors.push(error.message));
  page.on('console', message => {
    if (message.type() === 'error' && !message.text().includes('net::ERR_FAILED')) {
      browserErrors.push(message.text());
    }
  });
  let eventRequests = 0;
  await page.route('**/*', async route => {
    const request = route.request();
    if (request.method() === 'POST') {
      const body = request.postDataJSON();
      // The first request is the retention probe. Fail the background
      // indexer's own startup request once, then restore the real testnet RPC.
      if (body?.method === 'getEvents' && ++eventRequests === 2) {
        failedStartup = true;
        await route.abort('failed');
        return;
      }
    }
    await route.continue();
  });
}

async function synced(page) {
  await waitForCondition({
    operation: 'network-badge:synced', timeoutMs: 60_000, intervalMs: 250,
    observe: async () => ({
      badge: await page.locator('#sync-status').textContent(),
      walletState: await page.locator('body').getAttribute('data-wallet-state'),
      toasts: await page.locator('#toast-container').textContent(),
    }),
    isReady: ({ badge }) => badge === 'Synced',
  });
}

export async function run({ page, context, connectApp, ...wallet }) {
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'public connection requested a password');
  await driveWizard(page, context, { ...wallet, publicOnly: true });
  await synced(page);
  assert(failedStartup, 'startup RPC fault was not exercised');
  assert(navigations === 1, 'sync recovery must not rely on a page reload');
  console.log('OK: real Freighter public connection reaches Synced without a password');

  await page.locator('#storage-lock-btn').click();
  await page.getByTestId('storage-wallet-dialog').waitFor();
  await answerStorageWallet(page, context);
  await driveWizard(page, context, wallet);
  await synced(page);
  console.log('OK: unlocked private wallet reaches Synced');

  await page.locator('#storage-lock-btn').click();
  await page.waitForLoadState('domcontentloaded');
  await connectApp(page, { context, privateAccess: false });
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'locked reload requested a password');
  await synced(page);
  assert(browserErrors.length === 0, `Unexpected browser errors: ${browserErrors.join('\n')}`);
  console.log('OK: lock and reload continue syncing publicly');
}

import { driveWizard } from '../src/onboarding.mjs';
import { assert } from '../src/assert.mjs';
import { waitForCondition } from '../src/waits.mjs';

export const connectionOptions = { privateAccess: false };
let firstIndexedAt;
const errors = [];
export async function prepare({ page, context }) {
  // Only the runner's disposable restored profile: require a genuinely first
  // manual connection, with no remembered owner or cached chain data.
  const cdp = await context.newCDPSession(page);
  await cdp.send('Storage.clearDataForOrigin', {
    origin: new URL(process.env.APP_URL).origin, storageTypes: 'all',
  });
  await cdp.detach();
  await page.addInitScript(() => {
    document.addEventListener('DOMContentLoaded', () => {
      const observer = new MutationObserver(() => {
        if (document.querySelector('#sync-status')?.textContent === 'Synced' &&
            document.querySelector('#dashboard-feed')?.textContent.trim()) {
          window.publicReadyAt = Date.now();
          observer.disconnect();
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    });
  });
  page.on('console', message => {
    if (/\[INDEXER\] synced to ledger/.test(message.text())) firstIndexedAt ??= Date.now();
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', error => errors.push(error.message));
}

export async function run({ page, context, ...wallet }) {
  assert(await page.locator('#onboarding-modal').isVisible(), 'First connection must show onboarding');
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'Onboarding must start before asking for a password');
  await driveWizard(page, context, { ...wallet, publicOnly: true });
  await waitForCondition({
    operation: 'first-connect:public-feed', timeoutMs: 60_000, intervalMs: 100,
    observe: async () => ({
      synced: await page.locator('#sync-status').textContent(),
      feed: await page.locator('#dashboard-feed').textContent(),
      errors,
    }),
    isReady: ({ synced, feed }) => synced === 'Synced' && Boolean(feed.trim()),
  });
  assert(!await page.getByTestId('storage-wallet-dialog').isVisible(), 'public connection asked for a password');
  assert(errors.length === 0, `Browser errors: ${errors.join('\n')}`);
  const delay = await page.evaluate(() => window.publicReadyAt) - firstIndexedAt;
  console.log(`First connection: feed and badge updated ${delay} ms after indexer catch-up`);
  assert(firstIndexedAt && delay < 2500, 'Public dashboard remained stale after indexing completed');
  console.log('OK: first manual Freighter connection shows the feed without refreshing');
}

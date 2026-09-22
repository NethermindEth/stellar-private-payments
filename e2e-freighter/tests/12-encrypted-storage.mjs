// The shared profile starts encrypted. Exercise backup, wrong-key rejection,
// and real Freighter unlock without changing the other tests' profile copies.

import { randomBytes } from 'node:crypto';
import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { testDatabasePassword } from '../src/storage.mjs';

const log = createLogger('12-encrypted-storage');

export async function run({ page, context, approveOrWatch }) {
  const password = testDatabasePassword();
  const address = (await page.locator('#wallet-text').textContent()).trim();
  assert(/^G[A-Z2-7]{7}\.\.\.[A-Z2-7]{6}$/.test(address), 'wallet address is missing');
  assert(await page.evaluate(() => localStorage.getItem('spp.storage-access.v1')) === 'encrypted',
    'Freighter test profile is not encrypted');

  const explorer = `https://example.test/explorer/${randomBytes(8).toString('hex')}`;
  await page.locator('#open-settings-btn').click();
  await page.locator('#settings-explorer-input').fill(explorer);
  await page.locator('#settings-save-btn').click();
  await page.getByText('Settings saved', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Database security' }).click();
  const dialog = page.locator('dialog.storage-dialog');
  await dialog.waitFor({ state: 'visible' });
  await page.evaluate(() => {
    const createObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = blob => {
      window.__e2eKeyBackupBlob = blob;
      return createObjectURL(blob);
    };
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      if (this.download === 'spp-encrypted-key-backup.json') {
        window.__e2eKeyBackupFilename = this.download;
        return;
      }
      return click.call(this);
    };
  });
  await page.locator('#storage-password').fill(password);
  await page.locator('#storage-backup').click();
  await page.locator('#storage-feedback').filter({ hasText: 'Key backup download started' }).waitFor();
  const keyBackup = await page.evaluate(async () => ({
    filename: window.__e2eKeyBackupFilename,
    content: await window.__e2eKeyBackupBlob?.text(),
  }));
  assert(keyBackup.filename === 'spp-encrypted-key-backup.json', 'key backup filename is wrong');
  const envelope = JSON.parse(keyBackup.content);
  assert(envelope.format === 'spp-wrapped-database-key' && envelope.version === 1 && envelope.record,
    'key backup envelope is invalid');
  await page.locator('#storage-dismiss').click();
  await page.getByRole('button', { name: 'Lock database' }).click();

  await dialog.waitFor({ state: 'visible', timeout: 60_000 });
  await page.locator('#storage-wallet').waitFor({ state: 'visible' });
  await page.locator('#storage-password').fill('wrong-' + password);
  await page.locator('#storage-unlock').click();
  await page.locator('#storage-feedback').filter({ hasText: 'Incorrect password' }).waitFor();
  assert(await dialog.isVisible(), 'wrong password opened the database');

  await page.locator('#storage-wallet').click();
  await approveOrWatch(context, 'signMessage', { label: 'unlock storage wallet' });
  await dialog.waitFor({ state: 'hidden', timeout: 60_000 });
  await page.locator('body[data-wallet-state="ready"]').waitFor({ timeout: 60_000 });
  await page.locator('#wallet-text').filter({ hasText: address }).waitFor({ timeout: 60_000 });
  await page.locator('#open-settings-btn').click();
  assert(await page.locator('#settings-explorer-input').inputValue() === explorer,
    'encrypted SQLite setting was not preserved after wallet unlock');
  log.info('OK: encrypted profile, key backup, wrong-password rejection, and Freighter unlock preserved SQLite data');
}

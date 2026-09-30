// Run after building sdk/web: node integration-tests-app/scripts/test-storage-backup.mjs
// Uses an isolated Chromium profile and ephemeral signing keys; no network or funds.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { Keypair } from '@stellar/stellar-sdk';
import { exposeSigner } from '../src/testAccount.mjs';
import { CHROMIUM_PATH } from '../src/env.mjs';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const types = { '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  try {
    const file = resolve(root, `.${pathname}`);
    if (!(file === root || file.startsWith(`${root}/`)) || (!pathname.startsWith('/sdk/web/') && !pathname.startsWith('/app/js/') && pathname !== '/')) throw Error('not found');
    const body = pathname === '/' ? '<!doctype html><title>Encrypted backup test</title>' : await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'text/html', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: CHROMIUM_PATH });
  const page = await browser.newPage();
  const account = Keypair.random();
  const names = await exposeSigner(page, account);
  const url = `http://127.0.0.1:${server.address().port}/`;
  const load = async () => {
    await page.goto(url);
    await page.evaluate(async ({ names, address }) => {
      window.sdk = await import('/sdk/web/js/index.js');
      await sdk.default();
      window.backups = await import('/app/js/storage-backup.js');
      window.keys = await import('/app/js/storage-key.js');
      window.options = {
        storage: sdk.Storage, getAddress: async () => address,
        signMessage: (message, opts) => window[names.signMsgName](message, opts),
        verifySignature: (owner, message, sig) => window[names.verifyMsgName](owner, message, Array.from(sig)),
      };
    }, { names, address: account.publicKey() });
  };
  await load();
  await page.evaluate(async () => {
    const db = await keys.openWalletStorage(options);
    await db.call({ SetSetting: { key: 'backup-test', value_json: JSON.stringify('original-private-value') } });
    const root = await navigator.storage.getDirectory();
    let refused = false;
    try { const release = await backups.acquireStorageLease(root); await release(); }
    catch { refused = true; }
    if (!refused) throw Error('maintenance must reject an active OPFS handle');
    await db.close();
    const release = await backups.acquireStorageLease(root);
    try { window.backupText = await backups.exportStorageBackup({ root }); }
    finally { await release(); }
    const active = await keys.openWalletStorage(options);
    await active.call({ SetSetting: { key: 'backup-test', value_json: JSON.stringify('changed-after-backup') } });
    await active.close();
  });
  const text = await page.evaluate(() => backupText);
  assert.ok(!text.includes('original-private-value'), 'backup must not expose plaintext settings');
  await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const original = localStorage.getItem(backups.STORAGE_RECORD_KEY);
    localStorage.removeItem(backups.STORAGE_RECORD_KEY);
    try {
      await keys.openWalletStorage({ ...options, hasExistingStorage: () => backups.hasEncryptedStorage(root) });
      throw Error('missing envelope unexpectedly enrolled');
    } catch (error) { if (error.code !== 'storage-recovery-required') throw error; }
    localStorage.setItem(backups.STORAGE_RECORD_KEY, original);
    const backup = backups.parseBackup(backupText);
    const release = await backups.acquireStorageLease(root);
    try { await backups.importStorageBackup({ root, backup, validate: async record => {
      let value = JSON.stringify(record);
      const db = await keys.openWalletStorage({ ...options,
        records: { getItem: () => value, setItem: (_key, next) => { value = next; } },
      });
      try {
        if (await db.call('CheckIntegrity', 120000) !== 'Saved') throw Error('integrity check failed');
      } finally { await db.close(); }
    } }); } finally { await release(); }
  });
  await load();
  const value = await page.evaluate(async () => {
    const db = await keys.openWalletStorage(options);
    try { return await db.call({ GetSetting: 'backup-test' }); }
    finally { await db.close(); }
  });
  assert.equal(value.Setting, JSON.stringify('original-private-value'));
  await page.evaluate(async text => {
    const root = await navigator.storage.getDirectory();
    const saved = localStorage.getItem(backups.STORAGE_RECORD_KEY);
    const backup = backups.parseBackup(text);
    let rejected = false;
    try {
      await backups.importStorageBackup({ root, backup, validate: async record => {
        await keys.openWalletStorage({ ...options, verifySignature: async () => false,
          records: { getItem: () => JSON.stringify(record), setItem: () => { throw Error('must not write'); } },
        });
      } });
    } catch { rejected = true; }
    if (!rejected || localStorage.getItem(backups.STORAGE_RECORD_KEY) !== saved) throw Error('failed import changed active data');
    const corrupt = backups.parseBackup(text);
    const database = corrupt.files.find(file => file.bytes.length > 8192);
    if (!database) throw Error('test database file not found');
    database.bytes[database.bytes.length - 1] ^= 1;
    rejected = false;
    try {
      await backups.importStorageBackup({ root, backup: corrupt, validate: async record => {
        let value = JSON.stringify(record);
        const db = await keys.openWalletStorage({ ...options,
          records: { getItem: () => value, setItem: (_key, next) => { value = next; } },
        });
        try {
          if (await db.call('CheckIntegrity', 120000) !== 'Saved') throw Error('corrupted backup');
        } finally { await db.close(); }
      } });
    } catch { rejected = true; }
    if (!rejected || localStorage.getItem(backups.STORAGE_RECORD_KEY) !== saved) throw Error('corrupt backup changed active data');
    await backups.resetStorage({ root });
    if (await backups.hasEncryptedStorage(root) || localStorage.getItem(backups.STORAGE_RECORD_KEY)) throw Error('reset left encrypted storage behind');
  }, text);
  console.log('PASS: encrypted export, missing-envelope protection, staged import, integrity validation, reload, failed import preservation, reset');
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}

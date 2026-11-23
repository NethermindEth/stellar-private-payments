import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const app = new URL('../../app/', import.meta.url);
const { build } = createRequire(new URL('package.json', app))('esbuild');

async function panelBundle() {
  return build({
    entryPoints: [fileURLToPath(new URL('js/admin-gvk.js', app))],
    bundle: true,
    write: false,
    globalName: 'gvkPanel',
    plugins: [{
      name: 'synthetic-audit',
      setup(builder) {
        builder.onResolve({ filter: /\.\/(wasm-facade|admin-transactions)\.js$/ }, ({ path }) =>
          ({ path, namespace: 'fixture' }));
        builder.onLoad({ filter: /.*/, namespace: 'fixture' }, ({ path }) => ({
          contents: path.endsWith('admin-transactions.js')
            ? 'export const shortAddress = String, rpcServer = () => ({});'
            : `export const client = () => window.auditClient, readTokenDecimals = () => 0,
                getCurrentRpcUrl = () => '', parseTokenAmount = BigInt, storageWasLocked = () => false,
                isStorageUnlocked = () => true, STORAGE_STATE_EVENT = 'storage-state';`,
        }));
      },
    }],
  });
}

async function openPanel(t, { mode = 'traceable', count = 43, spendAt = null } = {}) {
  const browser = await chromium.launch({ channel: process.env.CHROMIUM_CHANNEL });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  // Time still flows; tests fast-forward past timers they must not wait on in real time.
  await page.clock.install();

  const html = await readFile(new URL('admin.html', app), 'utf8');
  await page.setContent(html.match(/<section id="global-view"[\s\S]*?<\/section>/)[0]);
  await page.locator('#global-view').evaluate((section) => { section.hidden = false; });
  await page.addScriptTag({ content: (await panelBundle()).outputFiles[0].text });
  await page.evaluate(async ({ mode, count, spendAt }) => {
    const pool = { poolContractId: 'pool', gvkMode: mode };
    window.calls = 0;
    window.auditClient = {
      contractConfig: () => ({ pools: [pool] }),
      poolContractsData: () => ({ pools: [{ fee: 0 }] }),
      noteKeyOwnerLookup: () => ({
        registryFullySynced: !!window.registryReady,
        owners: [{ noteKey: 'alice', address: 'registered-address', free() {} }],
        free() {},
      }),
      gvkAuthority: () => ({
        free() {},
        audit() {
          let ledger = 0;
          return {
            free() {},
            nextTx() {
              window.calls++;
              if (ledger === window.failAt) {
                window.failAt = null;
                throw Error('Cursor interrupted');
              }
              if (ledger === count) return null;
              ledger++;
              const note = { commitment: String(ledger), note: { pk: 'alice', amount: '0x10' } };
              const inputs = ledger === spendAt
                ? [{ nullifier: 'spent-first-note', note: { ...note, commitment: '1' } }]
                : [];
              return { ledger, inputs, outputs: [{ note }] };
            },
          };
        },
      }),
    };
    await window.gvkPanel.initGvkAuditPanel({ ensureCryptoReady: async () => {} });
  }, { mode, count, spendAt });
  const status = (value) => page.waitForFunction(
    (text) => document.querySelector('#gvkAuditStatus').textContent.includes(text), value,
  );
  const click = (id) => page.locator('#gvk' + id).click();
  await page.locator('#gvkPrivateKey').fill('a'.repeat(64));
  await click('AuditBtn');
  await status('Transactions 1–20');
  return { page, errors, status, click };
}

test('GVK paging, filter scans and graph selection', async (t) => {
  const { page, errors, status, click } = await openPanel(t);
  await page.evaluate(() => { window.failAt = 23; });
  await click('NextBtn');
  await status('Cursor interrupted');
  await click('NextBtn');
  await status('Transactions 21–40');
  assert.equal(await page.locator('#gvkAuditResults article').count(), 20);
  const calls = await page.evaluate(() => window.calls);
  await click('PrevBtn');
  await click('NextBtn');
  assert.equal(await page.evaluate(() => window.calls), calls);

  for (const [button, mark] of [
    ['ViewGraphBtn', 'path[data-gvk-note-id]'],
    ['ViewPkGraphBtn', 'path[data-gvk-pk-node]'],
  ]) {
    await click(button);
    const sameMark = await page.locator('#gvkAuditResults ' + mark).first().evaluate((node) => {
      node.dispatchEvent(new MouseEvent('click'));
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight' }));
      return node.isConnected;
    });
    assert.equal(sameMark, true);
    await status('Transactions 21–40');
  }
  await page.locator('#gvkFilterPk').fill('alice');
  await status('Transactions 1–20 of 43');
  await click('NextBtn');
  await click('NextBtn');
  await status('Transactions 41–43 of 43');
  assert.equal(await page.locator('#gvkNextBtn').isDisabled(), true);

  await page.locator('#gvkFilterPk').fill('missing');
  await click('FiltersClearBtn');
  await status('Transactions 1–20 of 43');
  await page.locator('#gvkFilterPk').fill('missing');
  await status('No matching transactions');
  await click('ViewNoteBtn');
  const download = page.waitForEvent('download');
  await click('ExportBtn');
  const csv = await readFile(await (await download).path(), 'utf8');
  assert.equal(csv.trimEnd().split('\r\n').length, 44);

  await page.locator('#gvkFilterPk').fill('registered-address');
  await status('No matching transactions');
  await page.evaluate(() => { window.registryReady = true; });
  // The owner retry backs off up to 60 s while the registry syncs; fire it now.
  await page.clock.fastForward(60_000);
  await status('Transactions 1–20 of 43');
  assert.deepEqual(errors, []);
});

test('GVK traceable notes reflect spends found on later pages', async (t) => {
  const { page, errors, status, click } = await openPanel(t, { count: 21, spendAt: 21 });
  const results = page.locator('#gvkAuditResults');
  await click('ViewNoteBtn');
  assert.equal(await results.getByText('No spend seen yet', { exact: true }).count(), 20);
  await click('ViewPkGraphBtn');
  await results.locator('path[data-gvk-pk-node]').first().dispatchEvent('click');
  await results.getByText('Balance in scanned transactions', { exact: true }).waitFor();

  await click('NextBtn');
  await status('Transactions 21–21 of 21');
  await click('PrevBtn');
  await status('Transactions 1–20 of 21');
  await results.locator('path[data-gvk-pk-node]').first().dispatchEvent('click');
  await results.getByText('Current balance', { exact: true }).waitFor();
  await click('ViewNoteBtn');
  assert.equal(await results.getByText('Spent', { exact: true }).count(), 2); // Header and one note.
  assert.equal(await results.getByText('Unspent', { exact: true }).count(), 19);
  assert.deepEqual(errors, []);
});

test('GVK view-only totals become complete after an empty fetch on a full page', async (t) => {
  const { page, errors, status, click } = await openPanel(t, { mode: 'viewOnly', count: 20 });
  const results = page.locator('#gvkAuditResults');
  const next = page.locator('#gvkNextBtn');
  await status('more available');
  assert.equal(await page.evaluate(() => window.calls), 20);
  await click('ViewNoteBtn');
  assert.equal(await results.getByText('Unknown', { exact: true }).count(), 20);
  await click('ViewPkGraphBtn');
  await results.locator('path[data-gvk-pk-node]').first().dispatchEvent('click');
  await results.getByText('Received in scanned transactions', { exact: true }).waitFor();

  await click('NextBtn');
  await status('Transactions 1–20 of 20');
  assert.equal(await page.evaluate(() => window.calls), 21);
  assert.equal(await next.isDisabled(), true);
  // The page is unchanged, so the selection survives the re-render; clicking again would deselect.
  await results.getByText('Total received', { exact: true }).waitFor();
  await click('ViewNoteBtn');
  assert.equal(await results.getByText('Unknown', { exact: true }).count(), 20);
  assert.deepEqual(errors, []);
});

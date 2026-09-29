/** Public browsing and syncing with a locked private vault, using real WASM/OPFS. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { resolve, extname, sep } from 'node:path';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';
const root = new URL('../../../', import.meta.url).pathname;
const sdkRoot = resolve(root, 'sdk/web');
const require = createRequire(resolve(root, 'app/package.json'));
const { xdr, nativeToScVal } = require('@stellar/stellar-sdk');
const event = index => ({
    id: `PUBLIC_CHAIN_EVENT_${index}`, ledger: index + 10, contractId: 'PUBLIC_POOL',
    topics: [xdr.ScVal.scvSymbol('LeafAdded').toXDR('base64')],
    value: xdr.ScVal.scvMap([
        ['index', nativeToScVal(BigInt(index), { type: 'u64' })],
        ['leaf', nativeToScVal(BigInt(index + 1), { type: 'u256' })],
        ['root', nativeToScVal(BigInt(index + 2), { type: 'u256' })],
    ].map(([key, val]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val }))).toXDR('base64'),
});
const { outputFiles } = await build({
    stdin: { contents: "export * from './js/wasm-facade.js';", resolveDir: resolve(root, 'app') },
    bundle: true, write: false, format: 'esm',
    plugins: [{ name: 'sdk-path', setup(b) {
        b.onResolve({ filter: /^stellar-private-payments$/ }, () => ({ path: '/sdk-proxy.js', external: true }));
        b.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'wallet', namespace: 'fixture' }));
        b.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({ contents: 'export class FreighterSigner {}' }));
    } }],
});
const html = `<!doctype html><body><button id="unlock">View private data</button><script type="module">
import * as facade from '/facade.js';
window.facade = facade;
window.appStorage = await facade.ensureStorage();
document.querySelector('#unlock').onclick = () => facade.ensurePrivateStorage().catch(e => window.unlockError = e.code || e.message);
window.ready = true;
</script></body>`;
const server = createServer(async (request, response) => {
    try {
        const path = new URL(request.url, 'http://localhost').pathname;
        let body; let type = 'text/javascript';
        if (path === '/') { body = html; type = 'text/html'; }
        else if (path === '/sdk-proxy.js') body = `export * from '/sdk/js/index.js'; export { default } from '/sdk/js/index.js'; import { Storage as Base } from '/sdk/js/index.js'; export const Storage = { connect: async options => { window.storage = await Base.connect(options); return window.storage; } };`;
        else if (path === '/facade.js') body = outputFiles[0].text;
        else {
            const file = resolve(sdkRoot, '.' + path.replace(/^\/sdk/, ''));
            if (!path.startsWith('/sdk/') || !file.startsWith(sdkRoot + sep)) throw Error('invalid path');
            body = await readFile(file);
            if (extname(file) === '.wasm') type = 'application/wasm';
        }
        response.writeHead(200, { 'Content-Type': type, 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' });
        response.end(body);
    } catch { response.writeHead(404); response.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
const checks = [];
try {
    browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/usr/bin/chromium', headless: true });
    const page = await browser.newPage();
    page.setDefaultTimeout(120_000);
    const load = async () => { await page.goto(`http://localhost:${server.address().port}/`); await page.waitForFunction(() => window.ready); };
    const call = request => page.evaluate(request => storage.call(request, 120_000), request);
    const saveEvent = async index => {
        assert.equal(await call({ SaveEvents: { events: [event(index)], cursor: `cursor-${index}`, latestLedger: index + 10 } }), 'Saved');
        assert.equal(await call('ProcessPendingState'), 'Saved');
    };
    const feed = () => call({ OperationalFeed: { limit: 100, asp_membership_contract_id: 'PUBLIC_POOL', public_key_registry_contract_id: 'REGISTRY' } });
    const snapshot = () => page.evaluate(async () => {
        const root = await navigator.storage.getDirectory(); const out = [];
        async function walk(dir) {
            for await (const [, h] of dir.entries()) {
                if (h.kind === 'directory') await walk(h);
                else {
                    const bytes = new Uint8Array(await (await h.getFile()).arrayBuffer());
                    out.push({ name: new TextDecoder().decode(bytes.subarray(0, 512)).split('\0')[0], text: new TextDecoder().decode(bytes), size: bytes.length });
                }
            }
        }
        await walk(root); return out;
    });
    await load();
    assert.equal(await page.getByTestId('storage-wallet-dialog').count(), 0);
    assert.equal(await page.evaluate(() => storage.status()), 'new');
    await page.evaluate(() => appStorage.setBootnodeConfig('https://public.example'));
    await saveEvent(0);
    assert.equal((await feed()).OperationalFeed.length, 1);
    await assert.rejects(call({ GetSetting: 'private-marker' }), /locked/);
    await page.click('#unlock');
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.waitForFunction(() => window.unlockError === 'unlock-cancelled');
    assert.equal((await feed()).OperationalFeed.length, 1);
    checks.push('fresh app opens and syncs public events without creating a password; cancellation preserves public access');

    const wallet = { context: { version: 1, address: 'G' + 'A'.repeat(55), origin: 'https://storage.test', salt: '01'.repeat(32) }, secret: 'ab'.repeat(32) };
    await page.evaluate(async wallet => {
        await storage.createWallet(wallet.context, wallet.secret);
        await facade.ensurePrivateStorage();
    }, wallet);
    await call({ SetSetting: { key: 'private-marker', value_json: JSON.stringify('PRIVATE_SECRET_MARKER_9384') } });
    await call({ RecordOperation: { address: 'PRIVATE_OWNER_9384', pool_contract_id: 'PUBLIC_POOL', op_type: 'sent', amount: '12345', direction: 'out', counterparty: 'PRIVATE_PEER_9384', tx_hash: null } });
    await page.evaluate(() => facade.lockStorage());
    await page.waitForFunction(() => window.ready && !facade.isStorageUnlocked());
    assert.equal(await page.getByTestId('storage-wallet-dialog').count(), 0);
    assert.equal(await page.evaluate(() => storage.status()), 'locked');
    for (const request of [{ GetSetting: 'private-marker' }, { PrivacyKeys: 'PRIVATE_OWNER_9384' }, { UserNotes: ['PRIVATE_OWNER_9384', 10] }, { ListOperations: { address: 'PRIVATE_OWNER_9384', pool_contract_id: 'PUBLIC_POOL', limit: 10 } }]) {
        await assert.rejects(call(request), /locked/);
    }
    await saveEvent(1);
    assert.equal((await feed()).OperationalFeed.length, 2);
    const files = await snapshot();
    assert(files.find(f => f.name === 'spp.public.db').text.includes('PUBLIC_CHAIN_EVENT_1'));
    for (const secret of ['PRIVATE_SECRET_MARKER_9384', 'PRIVATE_OWNER_9384', 'PRIVATE_PEER_9384']) {
        assert(files.every(f => !f.text.includes(secret)), `plaintext OPFS leak: ${secret}`);
    }
    checks.push('lock reloads into public mode; private calls fail closed; public syncing continues and OPFS contains no private markers');

    await assert.rejects(page.evaluate(wallet => storage.unlockWallet(wallet.context, 'cd'.repeat(32)), wallet));
    assert.equal((await feed()).OperationalFeed.length, 2);
    await page.evaluate(async wallet => {
        await storage.unlockWallet(wallet.context, wallet.secret);
        await facade.ensurePrivateStorage();
    }, wallet);
    assert.equal((await call({ GetSetting: 'private-marker' })).Setting, JSON.stringify('PRIVATE_SECRET_MARKER_9384'));
    assert.equal((await call({ ListOperations: { address: 'PRIVATE_OWNER_9384', pool_contract_id: 'PUBLIC_POOL', limit: 10 } })).Operations.length, 1);
    checks.push('wrong wallet secret leaves public access usable; correct wallet secret restores private data after locked sync');
    // An old installation has a complete encrypted vault and no public cache.
    // Reproduce that layout without changing the vault or its key records.
    await page.evaluate(async () => {
        await storage.call('ProcessPendingState', 120_000);
        await storage.close();
        const root = await navigator.storage.getDirectory();
        const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
        for await (const [name, handle] of opaque.entries()) {
            const header = new Uint8Array(await (await handle.getFile()).slice(0,512).arrayBuffer());
            const logical = new TextDecoder().decode(header).split('\0')[0];
            if (logical === 'spp.public.db' || logical === 'spp.public.db-journal') await opaque.removeEntry(name);
        }
    });
    await load();
    assert.equal(await page.evaluate(() => storage.status()), 'locked');
    assert.equal((await feed()).OperationalFeed.length, 0);
    await page.evaluate(async wallet => {
        await storage.unlockWallet(wallet.context, wallet.secret);
        await facade.ensurePrivateStorage();
    }, wallet);
    await call('ProcessPendingState');
    assert.equal((await feed()).OperationalFeed.length, 2);
    assert.equal((await call({ ListOperations: { address: 'PRIVATE_OWNER_9384', pool_contract_id: 'PUBLIC_POOL', limit: 10 } })).Operations.length, 1);
    checks.push('existing encrypted vault seeds a missing public cache on unlock without losing private history');
    // Losing the wallet record must never turn existing encrypted data into
    // a fresh profile or allow createWallet to overwrite it.
    await page.evaluate(async () => {
        await storage.close();
        const root = await navigator.storage.getDirectory();
        const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
        for await (const [name, handle] of opaque.entries()) {
            const header = new Uint8Array(await (await handle.getFile()).slice(0, 512).arrayBuffer());
            if (new TextDecoder().decode(header).split('\0')[0] === 'spp.key.db') await opaque.removeEntry(name);
        }
    });
    await load();
    assert.equal(await page.evaluate(() => storage.status()), 'recovery-required');
    const stranded = await snapshot();
    await assert.rejects(page.evaluate(wallet => storage.createWallet(wallet.context, wallet.secret), wallet), /existing local data/);
    assert.deepEqual(await snapshot(), stranded, 'missing wallet record must never cause implicit data deletion');
    checks.push('missing wallet record refuses creation and preserves encrypted bytes until explicit reset');
    await page.evaluate(() => storage.reset());
    await assert.rejects(call({ SaveSyncProgress: { metadata: [], fully_indexed: true } }), /storage reset/);
    await load();
    assert.equal(await page.evaluate(() => storage.status()), 'new');
    assert.equal((await feed()).OperationalFeed.length, 0);
    checks.push('explicit reset removes the public cache, private vault and enrolled key records');
    console.log(JSON.stringify({ ok: true, checks }, null, 2));
} finally {
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
}

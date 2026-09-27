/** Abruptly terminate the real WASM storage worker after an uncommitted DB
 * write reaches OPFS. The test-only loader pauses at the VFS boundary; it
 * neither changes production SQLite/VFS code nor simulates journal recovery.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { resolve, sep, extname } from 'node:path';
import { chromium } from 'playwright';

const sdkRoot = new URL('../../../sdk/web/', import.meta.url).pathname;
const loader = `
const write = FileSystemSyncAccessHandle.prototype.write;
FileSystemSyncAccessHandle.prototype.write = function(bytes, options) {
    const result = write.call(this, bytes, options);
    if (globalThis.armCrash && options?.at >= 4096) {
        const header = new Uint8Array(512);
        this.read(header, {at: 0});
        if (new TextDecoder().decode(header).split('\\0')[0] === 'spp.encrypted.db') {
            this.flush();
            console.log('TEST_UNCOMMITTED_DB_WRITE');
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
        }
    }
    return result;
};
await import('/sdk/dist/workers/storage-worker.js');
`;
const html = `<!doctype html><script type="module">
const OriginalWorker = window.Worker;
window.Worker = class extends OriginalWorker {
    constructor(...args) { super(...args); window.testWorker = this; }
};
const sdk = await import('/sdk/js/index.js'); await sdk.default();
window.storage = await sdk.Storage.connect({workerUrl:'/crash-worker.js'});
window.ready = true;
</script>`;
const server = createServer(async (request, response) => {
    try {
        const path = new URL(request.url, 'http://localhost').pathname;
        let body; let type = 'text/javascript';
        if (path === '/') { body = html; type = 'text/html'; }
        else if (path === '/crash-worker.js') body = loader;
        else {
            const file = resolve(sdkRoot, '.' + path.replace(/^\/sdk/, ''));
            if (!path.startsWith('/sdk/') || !file.startsWith(resolve(sdkRoot) + sep)) throw Error('invalid path');
            body = await readFile(file);
            if (extname(file) === '.wasm') type = 'application/wasm';
        }
        response.writeHead(200, { 'Content-Type': type, 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' });
        response.end(body);
    } catch { response.writeHead(404); response.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/usr/bin/chromium', headless: true });
    const page = await browser.newPage();
    page.setDefaultTimeout(120_000);
    await page.goto(`http://localhost:${server.address().port}/`);
    await page.waitForFunction(() => window.ready);
    const password = 'correct horse battery staple';
    await page.evaluate(async password => {
        await storage.create(password);
        await storage.call({SetSetting:{key:'crash-marker', value_json:JSON.stringify('committed')}});
    }, password);
    const worker = page.workers()[0];
    await worker.evaluate(() => { globalThis.armCrash = true; });
    const paused = page.waitForEvent('console', { predicate: message => message.text() === 'TEST_UNCOMMITTED_DB_WRITE', timeout: 120_000 });
    await page.evaluate(() => {
        // Larger than the 16 MiB page cache, forcing dirty pages to spill
        // before SQLite can commit this single-row transaction.
        window.writePending = storage.call({SetSetting:{key:'crash-marker', value_json:JSON.stringify('uncommitted'.repeat(3_000_000))}}, 120_000).catch(() => {});
    });
    await paused;
    await page.evaluate(() => window.testWorker.terminate());
    await page.reload();
    await page.waitForFunction(() => window.ready);
    assert.equal(await page.evaluate(() => storage.status()), 'locked');
    const snapshot = () => page.evaluate(async () => {
        const root = await navigator.storage.getDirectory();
        const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
        const files = [];
        for await (const [name, handle] of opaque.entries()) {
            const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
            const logical = new TextDecoder().decode(bytes.subarray(0,512)).split('\0')[0];
            files.push({name, logical, size:bytes.length, digest:Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))});
        }
        return files.sort((a,b) => a.name.localeCompare(b.name));
    });
    const hot = await snapshot();
    assert(hot.some(file => file.logical === 'spp.encrypted.db-journal' && file.size > 4096), 'abrupt kill must leave a real rollback journal');
    assert.equal(await page.evaluate(async () => {
        try { await storage.unlock('wrong password'); return false; } catch (error) { return error.code === 'wrong-password'; }
    }), true);
    assert.deepEqual(await snapshot(), hot, 'wrong password must preserve hot-journal bytes');
    await page.evaluate(password => storage.unlock(password), password);
    assert.equal(await page.evaluate(async () => (await storage.call({GetSetting:'crash-marker'})).Setting), JSON.stringify('committed'));
    await page.evaluate(async () => {
        await storage.call({SetSetting:{key:'after-recovery',value_json:'true'}});
        await storage.close();
    });
    await page.reload(); await page.waitForFunction(() => window.ready);
    await page.evaluate(password => storage.unlock(password), password);
    assert.equal(await page.evaluate(async () => (await storage.call({GetSetting:'after-recovery'})).Setting), 'true');
    await page.evaluate(() => storage.close());
    console.log('PASS: real SAH hot-journal recovery after worker termination mid-write, wrong-password non-mutation, subsequent durable writes');
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}

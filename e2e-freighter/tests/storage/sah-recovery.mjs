/** Abruptly terminate the real WASM storage worker after an uncommitted DB
 * write reaches OPFS. The test-only loader pauses at the VFS boundary; it
 * neither changes production SQLite/VFS code nor simulates journal recovery.
 */
import assert from 'node:assert/strict';
import { createStorageHarness, snapshotOPFS } from '../../src/storage-harness.mjs';

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
const harness = await createStorageHarness({ routes: { '/': html, '/crash-worker.js': loader } });
try {
    const page = harness.page;
    await page.goto(harness.origin);
    await page.waitForFunction(() => window.ready);
    const wallet = { context: { version: 1, address: 'G' + 'A'.repeat(55), origin: 'https://storage.test', salt: '01'.repeat(32) }, secret: 'ab'.repeat(32) };
    await page.evaluate(async wallet => {
        await storage.createWallet(wallet.context, wallet.secret);
        await storage.call({SetSetting:{key:'crash-marker', value_json:JSON.stringify('committed')}});
    }, wallet);
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
    const snapshot = () => snapshotOPFS(page);
    const hot = await snapshot();
    assert(hot.some(file => file.logical === 'spp.encrypted.db-journal' && file.bytes > 4096), 'abrupt kill must leave a real rollback journal');
    assert.equal(await page.evaluate(async () => {
        try { await storage.unlockWallet(await storage.walletContext(), 'cd'.repeat(32)); return false; } catch { return true; }
    }), true);
    assert.deepEqual(await snapshot(), hot, 'wrong wallet secret must preserve hot-journal bytes');
    await page.evaluate(wallet => storage.unlockWallet(wallet.context, wallet.secret), wallet);
    assert.equal(await page.evaluate(async () => (await storage.call({GetSetting:'crash-marker'})).Setting), JSON.stringify('committed'));
    await page.evaluate(async () => {
        await storage.call({SetSetting:{key:'after-recovery',value_json:'true'}});
        await storage.close();
    });
    await page.reload(); await page.waitForFunction(() => window.ready);
    await page.evaluate(wallet => storage.unlockWallet(wallet.context, wallet.secret), wallet);
    assert.equal(await page.evaluate(async () => (await storage.call({GetSetting:'after-recovery'})).Setting), 'true');
    await page.evaluate(() => storage.close());
    console.log('PASS: real SAH hot-journal recovery after worker termination mid-write, wrong-wallet-secret non-mutation, subsequent durable writes');
} finally {
    await harness.close();
}

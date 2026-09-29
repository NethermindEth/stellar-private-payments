/** Isolated browser checks for the wallet-only Freighter setup UI. */
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const { outputFiles } = await build({
    stdin: {
        contents: `export { unlockStorage, startAutoLock, MAX_BUSY_LOCK_DELAY_MS } from './js/storage-access.js';
            export { closeAndReload } from './js/storage-lock.js';
            export { beginStorageActivity } from './js/storage-activity.js';
            import { Keypair, hash } from '@stellar/stellar-sdk';
            export function setup(status = 'new', enrolled = false) {
                const key = Keypair.random();
                window.fault = null; window.signatures = 0; window.finished = false;
                window.signer = {
                    async getPublicKey() { return key.publicKey(); },
                    async signMessage(message) {
                        window.signatures++;
                        if (window.fault) throw Error('User declined');
                        const bytes = key.sign(hash(new TextEncoder().encode('Stellar Signed Message:\\n' + message)));
                        return { signerAddress: key.publicKey(), signedMessage: btoa(String.fromCharCode(...bytes)) };
                    }
                };
                window.storage = {
                    state: status, context: enrolled ? {} : null, created: 0,
                    async status() { return this.state; },
                    async createWallet(context, secret) { this.created++; this.context = context; this.secret = secret; this.state = 'unlocked'; },
                    async walletContext() { return this.context; },
                    async unlockWallet(context, secret) { if (secret !== this.secret) throw Error('wrong'); this.state = 'unlocked'; },
                    async reset() { this.context = null; this.state = 'new'; },
                };
            }`,
        resolveDir: new URL('../../../app', import.meta.url).pathname,
    },
    bundle: true, write: false, format: 'iife', globalName: 'access',
    plugins: [{ name: 'test-signer', setup(build) {
        build.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'signer', namespace: 'test' }));
        build.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export class FreighterSigner { constructor() { return globalThis.signer; } }' }));
    } }],
});
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/usr/bin/chromium', headless: true });
try {
    const page = await browser.newPage();
    await page.route('https://storage.test/**', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><body></body>' }));
    await page.goto('https://storage.test/');
    await page.addScriptTag({ content: outputFiles[0].text });
    const start = () => page.evaluate(() => { window.finished = false; window.opened = false; access.unlockStorage(storage, { onOpened: () => { window.opened = true; }, onReset: async () => { await storage.reset(); await access.closeAndReload(storage); } }).then(() => { window.finished = true; }); });
    await page.evaluate(() => access.setup()); await start();
    assert.equal(await page.locator('input[type=password]').count(), 0);
    assert.equal(await page.getByTestId('storage-auto-lock').inputValue(), '5');
    await page.evaluate(() => { window.fault = 'cancel'; });
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-wallet-error"]').textContent.includes('declined'));
    assert.equal(await page.evaluate(() => storage.context), null);
    await page.evaluate(() => { window.fault = null; window.signatures = 0; });
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => window.signatures), 2);
    assert.equal(await page.evaluate(() => window.opened), true);

    await page.evaluate(() => { storage.state = 'locked'; window.signatures = 0; }); await start();
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => window.signatures), 1);

    await page.evaluate(() => { storage.state = 'locked'; }); await start();
    await page.getByTestId('storage-reset').click();
    await Promise.all([
        page.waitForEvent('load'),
        page.getByTestId('storage-reset-confirm').click(),
    ]);
    assert.equal(await page.evaluate(() => typeof window.storage), 'undefined', 'reset must discard the old runtime and its sync cursors');
    await page.addScriptTag({ content: outputFiles[0].text });
    await page.evaluate(() => access.setup()); await start();
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => window.finished);
    const locks = await page.evaluate(() => {
        const originalNow = performance.now;
        const originalInterval = window.setInterval;
        let clock = performance.now(); let check; let locks = 0;
        Object.defineProperty(performance, 'now', { configurable: true, value: () => clock });
        window.setInterval = callback => { check = callback; return 0; };
        try {
            localStorage.setItem('spp.autoLockMinutes', '5');
            access.startAutoLock(() => { locks++; });
            const release = access.beginStorageActivity();
            clock += 600_000; check();
            if (locks !== 0) throw Error('auto-lock interrupted foreground work');
            release();
            clock += 299_000; check();
            if (locks !== 0) throw Error('auto-lock ignored completion grace period');
            clock += 2_000; check(); check();
            return locks;
        } finally { Object.defineProperty(performance, 'now', { configurable: true, value: originalNow }); window.setInterval = originalInterval; }
    });
    assert.equal(locks, 1, 'idle lock runs once after foreground work finishes');
    const cappedLocks = await page.evaluate(() => {
        const originalNow = performance.now;
        const originalInterval = window.setInterval;
        let clock = performance.now(); let check; let locks = 0;
        Object.defineProperty(performance, 'now', { configurable: true, value: () => clock });
        window.setInterval = callback => { check = callback; return 0; };
        const release = access.beginStorageActivity();
        const stop = access.startAutoLock(() => { locks++; });
        try {
            clock += 300_000 + access.MAX_BUSY_LOCK_DELAY_MS - 1; check();
            if (locks) throw Error('busy grace period ended early');
            clock += 2; check(); check();
            return locks;
        } finally {
            stop(); release();
            Object.defineProperty(performance, 'now', { configurable: true, value: originalNow });
            window.setInterval = originalInterval;
        }
    });
    assert.equal(cappedLocks, 1, 'stuck operations cannot defer idle locking forever');


    await page.evaluate(() => {
        access.setup('unencrypted');
        const create = storage.createWallet;
        storage.createWallet = async function(context, secret) {
            await create.call(this, context, secret);
            this.state = 'locked';
            throw Error('Legacy database migration failed; the original plaintext data is preserved.');
        };
    });
    await start();
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-wallet-dialog"]').dataset.mode === 'locked');
    assert.match(await page.getByTestId('storage-wallet-error').textContent(), /plaintext data is preserved/);
    await page.getByTestId('storage-wallet-submit').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => storage.created), 1, 'migration retry must reuse its wallet key');

    await page.evaluate(() => access.setup('recovery-required')); await start();
    assert.equal(await page.getByTestId('storage-wallet-submit').count(), 0);
    assert.match(await page.getByTestId('storage-wallet-dialog').textContent(), /Restore a complete browser-profile backup/);
    assert.equal(await page.evaluate(() => storage.created), 0);
    console.log('PASS: wallet-only setup, approval retry, unlock, explicit reset, migration retry, missing-record protection and bounded inactivity locking');
} finally { await browser.close(); }

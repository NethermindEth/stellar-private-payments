/** Isolated browser checks for the password-first Freighter setup UI. */
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const { outputFiles } = await build({
    stdin: {
        contents: `export { unlockStorage, startAutoLock, MAX_BUSY_LOCK_DELAY_MS } from './js/storage-access.js';
            export { beginStorageActivity } from './js/storage-activity.js';
            export { mountStorageMethods } from './js/storage-methods.js';
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
                    async create(password) { this.password = password; this.created++; this.state = 'unlocked'; },
                    async unlock(password) { if (password !== this.password) throw Object.assign(Error('wrong'), {code:'wrong-password'}); this.state = 'unlocked'; },
                    async walletContext() { return this.context; },
                    async passkeyContext() { return null; },
                    async removeWallet(password) { if (password !== this.password) throw Error('wrong password'); this.context = null; },
                    async enrollWallet(password, context, secret) { if (password !== this.password) throw Error('wrong'); this.context = context; this.secret = secret; },
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
    const start = () => page.evaluate(() => { window.finished = false; window.opened = false; access.unlockStorage(storage, { onOpened: () => { window.opened = true; } }).then(() => { window.finished = true; }); });
    const password = 'correct horse battery staple';
    const create = async (count = 1) => {
        await page.getByTestId('storage-password-input').fill(password);
        await page.getByTestId('storage-password-confirm').fill(password);
        await page.getByTestId('storage-password-submit').click();
        await page.getByTestId('storage-freighter-enable').waitFor();
        assert.equal(await page.evaluate(() => storage.created), count);
        assert.equal(await page.evaluate(() => window.finished), false);
        assert.equal(await page.evaluate(() => window.opened), true, 'auto-lock can start before enrollment finishes');
    };
    await page.evaluate(() => access.setup()); await start(); await create();
    await page.getByTestId('storage-freighter-skip').click();
    await page.getByTestId('storage-passkey-skip').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => storage.context), null);

    await page.evaluate(() => access.setup()); await start(); await create();
    await page.evaluate(() => { window.fault = 'cancel'; });
    await page.getByTestId('storage-freighter-enable').click();
    await page.getByTestId('storage-freighter-error').waitFor({ state: 'visible' });
    assert.equal(await page.getByTestId('storage-freighter-skip').isEnabled(), true);
    assert.equal(await page.evaluate(() => storage.context), null);
    await page.evaluate(() => { window.fault = null; window.signatures = 0; });
    await page.getByTestId('storage-freighter-enable').click();
    await page.getByTestId('storage-passkey-skip').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => window.signatures), 2);
    await page.evaluate(async () => {
        const panel = document.createElement('div'); document.body.appendChild(panel);
        await access.mountStorageMethods(panel, storage);
    });
    const oldSalt = await page.evaluate(() => storage.context.salt);
    await page.getByTestId('storage-method-password').fill(password);
    await page.getByTestId('storage-method-freighter-replace').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-method-message"]').textContent.includes('access saved'));
    assert.notEqual(await page.evaluate(() => storage.context.salt), oldSalt);
    await page.getByTestId('storage-method-password').fill(password);
    await page.getByTestId('storage-method-freighter-remove').click();
    await page.getByTestId('storage-method-freighter-enable').waitFor();
    assert.equal(await page.evaluate(() => storage.context), null);
    await page.getByTestId('storage-method-password').fill(password);
    await page.getByTestId('storage-method-freighter-enable').click();
    await page.getByTestId('storage-method-freighter-replace').waitFor();


    await page.evaluate(() => { storage.state = 'locked'; }); await start();
    await page.getByTestId('storage-freighter-unlock').click();
    await page.waitForFunction(() => window.finished);
    assert.equal(await page.evaluate(() => storage.state), 'unlocked');

    await page.evaluate(() => { storage.state = 'locked'; window.fault = 'cancel'; }); await start();
    await page.getByTestId('storage-freighter-unlock').click();
    await page.getByTestId('storage-password-error').waitFor({ state: 'visible' });
    await page.getByTestId('storage-password-input').fill(password);
    await page.getByTestId('storage-password-submit').click();
    await page.waitForFunction(() => window.finished);

    await page.evaluate(() => { storage.state = 'locked'; }); await start();
    await page.getByTestId('storage-password-forgot').click();
    await page.getByTestId('storage-reset-confirm').click();
    await create(2);
    assert.equal(await page.evaluate(() => storage.context), null);
    await page.getByTestId('storage-freighter-skip').click();
    await page.getByTestId('storage-passkey-skip').click();
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
        document.body.replaceChildren(); access.setup('unencrypted');
        storage.create = async function(password) {
            this.created++; this.password = password; this.state = 'locked';
            throw Error('Legacy database migration failed; the original plaintext data is preserved.');
        };
        storage.unlock = async function() {
            this.attempts = (this.attempts || 0) + 1;
            throw Error('Legacy database migration failed; this app has no local-data export; reset deletes the original too.');
        };
    });
    await start();
    await page.getByTestId('storage-password-input').fill(password);
    await page.getByTestId('storage-password-confirm').fill(password);
    await page.getByTestId('storage-password-submit').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-password-submit"]').textContent === 'Unlock');
    assert.match(await page.getByTestId('storage-password-error').textContent(), /plaintext data is preserved/);
    await page.getByTestId('storage-password-input').fill(password);
    await page.getByTestId('storage-password-submit').click();
    await page.waitForFunction(() => storage.attempts === 1);
    assert.equal(await page.evaluate(() => storage.created), 1, 'retry must unlock rather than create again');
    assert.match(await page.getByTestId('storage-password-error').textContent(), /no local-data export/);
    console.log('PASS: method replacement/removal, guarded inactivity locking; password-first setup, skip, enrollment retry, wallet unlock, password fallback, reset');
} finally { await browser.close(); }

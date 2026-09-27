/** Isolated browser checks for the password-first Freighter setup UI. */
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const { outputFiles } = await build({
    stdin: {
        contents: `export { unlockStorage } from './js/storage-access.js';
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
    const start = () => page.evaluate(() => { window.finished = false; access.unlockStorage(storage).then(() => { window.finished = true; }); });
    const password = 'correct horse battery staple';
    const create = async (count = 1) => {
        await page.getByTestId('storage-password-input').fill(password);
        await page.getByTestId('storage-password-confirm').fill(password);
        await page.getByTestId('storage-password-submit').click();
        await page.getByTestId('storage-freighter-enable').waitFor();
        assert.equal(await page.evaluate(() => storage.created), count);
        assert.equal(await page.evaluate(() => window.finished), false);
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
    console.log('PASS: password-first setup, skip, enrollment retry, wallet unlock, password fallback, reset');
} finally { await browser.close(); }

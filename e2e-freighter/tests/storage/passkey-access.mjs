/** Real WebAuthn PRF + WASM/OPFS storage, with a Chromium virtual authenticator.
 * Run after building sdk/web. No passkey results or crypto are mocked in this test.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { resolve, extname, sep } from 'node:path';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const root = new URL('../../../', import.meta.url).pathname;
const sdkRoot = resolve(root, 'sdk/web');
const { outputFiles } = await build({
    stdin: { contents: "export { unlockStorage } from './js/storage-access.js'; export { unlockPasskey } from './js/storage-passkey.js';", resolveDir: resolve(root, 'app') },
    bundle: true, write: false, format: 'esm',
    plugins: [{ name: 'unused-freighter', setup(build) {
        build.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'signer', namespace: 'test' }));
        build.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export class FreighterSigner { constructor() { throw Error("Freighter is not part of this test"); } }' }));
    } }],
});
const html = `<!doctype html><body><script type="module">
import * as sdk from '/sdk/js/index.js';
import * as access from '/ui.js';
await sdk.default();
window.storage = await sdk.Storage.connect(); window.access = access; window.finished = false;
access.unlockStorage(storage).then(() => { window.finished = true; });
</script></body>`;
const server = createServer(async (request, response) => {
    try {
        const path = new URL(request.url, 'http://localhost').pathname;
        let body; let type;
        if (path === '/') { body = html; type = 'text/html'; }
        else if (path === '/ui.js') { body = outputFiles[0].text; type = 'text/javascript'; }
        else {
            const file = resolve(sdkRoot, '.' + path.replace(/^\/sdk/, ''));
            if (!path.startsWith('/sdk/') || !file.startsWith(sdkRoot + sep)) throw Error('Invalid path');
            body = await readFile(file);
            type = extname(file) === '.wasm' ? 'application/wasm' : 'text/javascript';
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
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const addAuthenticator = async hasPrf => (await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
        protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb',
        hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
        automaticPresenceSimulation: true, hasPrf,
    } })).authenticatorId;
    let authenticatorId = await addAuthenticator(false);
    const password = 'correct horse battery staple';
    const replacement = 'replacement password for local data';
    const marker = 'PASSKEY_ENCRYPTED_STORAGE_TEST';
    const status = () => page.evaluate(() => storage.status());
    const context = () => page.evaluate(async () => (await storage.passkeyContext()) ?? null);
    const done = () => page.waitForFunction(() => window.finished);
    const reload = async () => {
        await page.evaluate(() => storage.close());
        await page.reload();
        await page.getByTestId('storage-password-input').waitFor();
        assert.equal(await status(), 'locked');
    };
    const create = async () => {
        await page.getByTestId('storage-password-input').fill(password);
        await page.getByTestId('storage-password-confirm').fill(password);
        assert.equal(await page.getByTestId('storage-auto-lock').inputValue(), '5');
        await page.getByTestId('storage-password-submit').click();
        await page.getByTestId('storage-freighter-skip').click();
        await page.getByTestId('storage-passkey-enable').waitFor();
        assert.equal(await status(), 'unlocked');
    };
    await page.goto(`http://localhost:${server.address().port}/`);
    await create();
    await page.getByTestId('storage-passkey-enable').click();
    await page.getByTestId('storage-passkey-error').waitFor({ state: 'visible' });
    assert.match(await page.getByTestId('storage-passkey-error').textContent(), /does not support encrypted storage/);
    assert.equal(await context(), null);
    assert(await page.getByTestId('storage-passkey-skip').isEnabled());
    checks.push('unsupported PRF leaves password setup intact and enrollment retryable');

    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    authenticatorId = await addAuthenticator(true);
    await page.getByTestId('storage-passkey-enable').click();
    await done();
    const enrolled = await context();
    assert.equal(enrolled.version, 1);
    const credentials = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
    assert.equal(credentials.length, 1);
    assert(credentials[0].signCount >= 1, 'creation must be followed by a real assertion');
    checks.push('real WebAuthn creation and PRF assertion enroll a passkey');

    await page.evaluate(async ({ marker, password }) => {
        await storage.call({ SetSetting: { key: 'passkey-test', value_json: JSON.stringify(marker) } });
        await storage.enrollWallet(password, {
            version: 1, address: 'G' + 'A'.repeat(55), origin: location.origin, salt: '03'.repeat(32),
        }, 'ef'.repeat(32));
    }, { marker, password });
    await reload();
    assert.equal(await page.getByTestId('storage-freighter-unlock').isVisible(), true);
    await page.getByTestId('storage-passkey-unlock').click();
    await done();
    assert.equal(await status(), 'unlocked');
    assert.equal(await page.evaluate(async () => (await storage.call({ GetSetting: 'passkey-test' })).Setting), JSON.stringify(marker));
    checks.push('passkey unlock reopens the actual encrypted OPFS database after reload');

    await page.evaluate(({ password, replacement }) => storage.changePassword(password, replacement), { password, replacement });
    await reload();
    await page.getByTestId('storage-passkey-unlock').click(); await done();
    assert.deepEqual(await context(), enrolled);
    checks.push('password changes preserve passkey access');

    await reload();
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
    // Abort a real pending WebAuthn request; no synthetic credential is returned.
    await page.evaluate(() => {
        const original = navigator.credentials.get;
        navigator.credentials.get = function(options) {
            navigator.credentials.get = original;
            return original.call(this, { ...options, signal: AbortSignal.timeout(200) });
        };
    });
    await page.getByTestId('storage-passkey-unlock').click();
    await page.getByTestId('storage-password-error').waitFor({ state: 'visible' });
    assert.match(await page.getByTestId('storage-password-error').textContent(), /cancelled or unavailable/);
    assert.equal(await status(), 'locked');
    assert.deepEqual(await context(), enrolled);
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
    await page.getByTestId('storage-password-input').fill(replacement);
    await page.getByTestId('storage-password-submit').click(); await done();
    checks.push('cancelled WebAuthn unlock stays locked and allows password fallback');

    await reload();
    assert.equal(await page.evaluate(async () => {
        try { await storage.unlockPasskey(await storage.passkeyContext(), '00'.repeat(32)); return false; }
        catch { return true; }
    }), true);
    assert.equal(await status(), 'locked');
    await page.evaluate(async () => storage.unlockWallet(await storage.walletContext(), 'ef'.repeat(32)));
    assert.equal(await status(), 'unlocked');
    checks.push('wrong passkey secret is rejected and Freighter access still works');

    await reload();
    await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
    // A missing credential is tested with a short browser timeout.
    await page.evaluate(() => {
        const original = navigator.credentials.get;
        navigator.credentials.get = function(options) {
            navigator.credentials.get = original;
            return original.call(this, { ...options, signal: AbortSignal.timeout(200) });
        };
    });
    await page.getByTestId('storage-passkey-unlock').click();
    await page.getByTestId('storage-password-error').waitFor({ state: 'visible' });
    assert.equal(await status(), 'locked');
    await page.getByTestId('storage-password-forgot').click();
    await page.getByTestId('storage-reset-confirm').click();
    await create();
    assert.equal(await context(), null);
    assert.equal(await page.evaluate(async () => (await storage.walletContext()) ?? null), null);
    await page.getByTestId('storage-passkey-skip').click(); await done();
    await reload();
    assert.equal(await page.getByTestId('storage-passkey-unlock').count(), 0);
    assert.equal(await page.getByTestId('storage-freighter-unlock').count(), 0);
    await page.getByTestId('storage-password-input').fill(password);
    await page.getByTestId('storage-password-submit').click(); await done();
    assert.equal(await page.evaluate(async () => (await storage.call({ GetSetting: 'passkey-test' })).Setting), undefined);
    checks.push('missing passkey cannot unlock; reset removes both optional envelopes and supports password-only setup');
    await page.evaluate(() => storage.close());
    console.log(JSON.stringify({ passed: true, checks }, null, 2));
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}

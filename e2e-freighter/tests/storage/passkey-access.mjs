/** Real WebAuthn PRF + WASM/OPFS storage, with a Chromium virtual authenticator.
 * Run after building sdk/web. No passkey results or crypto are mocked in this test.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { resolve, extname, sep } from 'node:path';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const root = new URL('../../../', import.meta.url).pathname;
const sdkRoot = resolve(root, 'sdk/web');
const { outputFiles } = await build({
    stdin: { contents: "export { unlockStorage } from './js/storage-access.js'; export { unlockPasskey } from './js/storage-passkey.js'; export { mountStorageMethods } from './js/storage-methods.js';", resolveDir: resolve(root, 'app') },
    bundle: true, write: false, format: 'esm',
    plugins: [{ name: 'unused-freighter', setup(build) {
        build.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'signer', namespace: 'test' }));
        build.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export class FreighterSigner { constructor() { throw Error("Freighter is not part of this test"); } }' }));
    } }],
});
const html = `<!doctype html><body><div id="methods"></div><script type="module">
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
        assert.equal(await page.evaluate(async () => {
            try { await storage.status(); return false; } catch (error) { return /closed/.test(String(error)); }
        }), true, 'closed worker must reject status before touching its released VFS');
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
    let enrolled = await context();
    assert.equal(enrolled.version, 1);
    const credentials = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
    assert.equal(credentials.length, 1);
    assert(credentials[0].signCount >= 2, 'enrollment must verify two real PRF assertions');
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

    // Settings can replace and revoke an envelope without destroying data.
    await page.evaluate(() => access.mountStorageMethods(document.getElementById('methods'), storage));
    await page.getByTestId('storage-method-password').fill('not the password');
    await page.getByTestId('storage-method-passkey-remove').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-method-message"]').textContent.includes('wrong password'));
    assert.deepEqual(await context(), enrolled);
    await page.getByTestId('storage-method-password').fill(replacement);
    await page.getByTestId('storage-method-passkey-replace').click();
    await page.waitForFunction(() => document.querySelector('[data-testid="storage-method-message"]').textContent.includes('access saved'));
    const oldEnrollment = enrolled;
    enrolled = await context();
    assert.notEqual(enrolled.credentialId, oldEnrollment.credentialId);
    assert.equal(await page.evaluate(async old => {
        try { await storage.unlockPasskey(old, '00'.repeat(32)); return false; } catch { return true; }
    }, oldEnrollment), true);
    await page.getByTestId('storage-method-password').fill(replacement);
    await page.getByTestId('storage-method-passkey-remove').click();
    await page.getByTestId('storage-method-passkey-enable').waitFor();
    assert.equal(await context(), null);
    assert(await page.evaluate(() => storage.walletContext()), 'removing a passkey must preserve Freighter');
    await page.getByTestId('storage-method-password').fill(replacement);
    await page.getByTestId('storage-method-passkey-enable').click();
    await page.getByTestId('storage-method-passkey-replace').waitFor();
    enrolled = await context();
    checks.push('Settings authenticates removal, replaces and re-enables passkeys without deleting data or Freighter access');

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

    // Remove only the password row in the plaintext key database while closed.
    // Keep both optional envelopes and the encrypted database byte-for-byte.
    const removePasswordRecord = async () => {
        await page.evaluate(() => storage.close());
        const fixture = await page.evaluate(async () => {
            const root = await navigator.storage.getDirectory();
            const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
            for await (const [name, handle] of opaque.entries()) {
                const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
                if (new TextDecoder().decode(bytes.subarray(0, 4096)).split('\0')[0] === 'spp.key.db') {
                    return { name, bytes: Array.from(bytes) };
                }
            }
            throw Error('key database fixture not found');
        });
        const original = Buffer.from(fixture.bytes);
        const updated = execFileSync('python3', ['-c',
            'import sqlite3,sys; c=sqlite3.connect(":memory:"); c.deserialize(sys.stdin.buffer.read()); c.execute("DELETE FROM password_record"); c.commit(); sys.stdout.buffer.write(c.serialize())'],
            { input: original.subarray(4096) });
        await page.evaluate(async ({ name, bytes }) => {
            const root = await navigator.storage.getDirectory();
            const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
            const writer = await (await opaque.getFileHandle(name)).createWritable();
            await writer.write(new Uint8Array(bytes)); await writer.close();
        }, { name: fixture.name, bytes: Array.from(Buffer.concat([original.subarray(0, 4096), updated])) });
        await page.reload();
        await page.getByTestId('storage-recovery-reset').waitFor();
        assert.equal(await status(), 'recovery-required');
        assert.equal(await page.evaluate(async () => {
            try { await storage.recoverPassword('unauthorized password'); return false; } catch { return true; }
        }), true, 'recovery requires a successful optional-method unlock');
    };
    for (const method of ['passkey', 'wallet']) {
        await removePasswordRecord();
        if (method === 'passkey') {
            await page.getByTestId('storage-passkey-unlock').click();
        } else {
            await page.evaluate(async () => storage.unlockWallet(await storage.walletContext(), 'ef'.repeat(32)));
            // Exercise the dialog for a handle already unlocked for recovery.
            await page.evaluate(() => {
                document.querySelector('[data-testid="storage-password-dialog"]').remove();
                access.unlockStorage(storage).then(() => { window.finished = true; });
            });
        }
        await page.getByTestId('storage-password-confirm').waitFor();
        assert.equal(await status(), 'password-recovery-required');
        assert.equal(await page.evaluate(async () => {
            try { await storage.recoverPassword('short'); return false; } catch { return true; }
        }), true);
        await page.getByTestId('storage-password-input').fill(replacement);
        await page.getByTestId('storage-password-confirm').fill(replacement);
        await page.getByTestId('storage-password-submit').click(); await done();
        assert.equal(await status(), 'unlocked');
        assert.equal(await page.evaluate(async () => {
            try { await storage.recoverPassword('must not replace existing password'); return false; } catch { return true; }
        }), true);
        assert.deepEqual(await context(), enrolled);
        assert(await page.evaluate(() => storage.walletContext()));
        await reload();
        await page.getByTestId('storage-password-input').fill(replacement);
        await page.getByTestId('storage-password-submit').click(); await done();
        assert.equal(await page.evaluate(async () => (await storage.call({ GetSetting: 'passkey-test' })).Setting), JSON.stringify(marker));
        // Method management is usable with the restored password.
        await page.evaluate(async password => {
            const context = await storage.walletContext();
            await storage.removeWallet(password);
            await storage.enrollWallet(password, context, 'ef'.repeat(32));
        }, replacement);
    }
    checks.push('passkey and wallet recovery restore password access, preserve data and methods, reject unauthorized recovery, and support method management');

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
    const encryptedBefore = await page.evaluate(async () => {
        const root = await navigator.storage.getDirectory();
        const pool = await root.getDirectoryHandle('.opfs-sahpool-encrypted');
        const opaque = await pool.getDirectoryHandle('.opaque');
        let found = false; let digest;
        for await (const [name, handle] of opaque.entries()) {
            const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
            const logical = new TextDecoder().decode(bytes.subarray(0, 4096)).split('\0')[0];
            if (logical === 'spp.key.db') { await opaque.removeEntry(name); found = true; }
            if (logical === 'spp.encrypted.db') digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
        }
        if (!found || !digest) throw Error('test fixture could not find OPFS files');
        return digest;
    });
    await page.reload();
    await page.getByTestId('storage-recovery-reset').waitFor();
    assert.equal(await status(), 'recovery-required');
    assert.equal(await page.evaluate(async password => {
        try { await storage.create(password); return false; } catch { return true; }
    }, password), true, 'create must not delete orphaned encrypted data');
    await page.evaluate(() => storage.close());
    const encryptedAfter = await page.evaluate(async () => {
        const root = await navigator.storage.getDirectory();
        const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
        for await (const handle of opaque.values()) {
            const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
            if (new TextDecoder().decode(bytes.subarray(0, 4096)).split('\0')[0] === 'spp.encrypted.db') {
                return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
            }
        }
    });
    assert.deepEqual(encryptedAfter, encryptedBefore);
    checks.push('missing key record requires explicit recovery; failed create preserves encrypted bytes');
    console.log(JSON.stringify({ passed: true, checks }, null, 2));
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}

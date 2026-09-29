#!/usr/bin/env node
/** Exercise real SDK WASM/OPFS using the shared Playwright storage harness.
 * --legacy-db PATH imports an earlier plaintext wallet; --legacy-gvk FILE
 * checks that its GVK authority survives. --package-root PATH tests an
 * extracted npm package without loading SDK files from the source tree.
 */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createStorageHarness, snapshotOPFS } from '../../src/storage-harness.mjs';

const { values: args } = parseArgs({ options: {
  artifacts: { type: 'string' }, binary: { type: 'string' }, browser: { type: 'string', default: 'chromium' },
  'legacy-db': { type: 'string' }, 'legacy-gvk': { type: 'string' },
  'package-root': { type: 'string' }, 'backend-version-fault': { type: 'boolean' },
} });
if (!args.artifacts) throw Error('--artifacts is required');
const artifacts = resolve(args.artifacts);
const harness = await createStorageHarness({
  artifacts, binary: args.binary, browser: args.browser,
  sdkRoot: args['package-root'] ? resolve(args['package-root']) : undefined,
  transformResponse: args['backend-version-fault'] ? (path, body) => {
    if (path.endsWith('/storage-worker-module_bg.wasm')) {
      // Preserve the WASM layout, changing only the served version string.
      const version = body.toString('latin1').match(/SQLite3 Multiple Ciphers [0-9]+\.[0-9]+\.[0-9]+/)?.[0];
      assert(version, 'linked cipher version string must exist');
      body.write(version.replace(/[0-9]/g, '0'), body.indexOf(version), 'latin1');
    }
    return body;
  } : undefined,
});
const WALLET_CONTEXT = { version: 1, address: `G${'A'.repeat(55)}`, origin: harness.origin, salt: '01'.repeat(32) };
const WALLET_SECRET = 'ab'.repeat(32);
const ctx = { marker: 'PROTECTED_OPFS_INTEGRATION_01b8af6d', checks: [] };
ctx.load = async (page = harness.page) => {
  await page.goto(harness.origin);
  await page.evaluate(async () => { window.sdk = await import('/sdk/js/index.js'); await sdk.default(); });
};
ctx.connect = () => harness.page.evaluate(async () => { window.storage = await sdk.Storage.connect(); return storage.status(); });
ctx.status = () => harness.page.evaluate(() => storage.status());
ctx.create = () => harness.page.evaluate(([context, secret]) => storage.createWallet(context, secret), [WALLET_CONTEXT, WALLET_SECRET]);
ctx.unlock = () => harness.page.evaluate(([context, secret]) => storage.unlockWallet(context, secret), [WALLET_CONTEXT, WALLET_SECRET]);
ctx.outcome = (operation, ...values) => harness.page.evaluate(async ({ operation, values }) => {
  try { await storage[operation](...values); return 'ok'; }
  catch (error) { return error.code || String(error); }
}, { operation, values });
ctx.setMarker = () => harness.page.evaluate(marker => storage.call({ SetSetting: { key: 'integration-protected', value_json: JSON.stringify(marker) } }), ctx.marker);
ctx.marked = async () => (await harness.page.evaluate(() => storage.call({ GetSetting: 'integration-protected' }))).Setting === JSON.stringify(ctx.marker);
ctx.close = () => harness.page.evaluate(async () => { await storage.close(); storage.free(); window.storage = null; });
ctx.snapshot = () => snapshotOPFS(harness.page, { secrets: ctx.secrets ?? [ctx.marker] });
// Older versions kept spp.db in a slot of the default OPFS pool, behind
// its 4096-byte header containing the logical filename and file flags.
ctx.injectLegacy = bytes => harness.page.evaluate(async base64 => {
  const data = Uint8Array.from(atob(base64), char => char.charCodeAt(0));
  const root = await navigator.storage.getDirectory();
  const opaque = await (await root.getDirectoryHandle('.opfs-sahpool', { create: true })).getDirectoryHandle('.opaque', { create: true });
  const header = new Uint8Array(4096);
  header.set(new TextEncoder().encode('spp.db'));
  new DataView(header.buffer).setUint32(512, 0x106);
  const file = await opaque.getFileHandle('legacyslot000000', { create: true });
  const writable = await file.createWritable();
  await writable.write(header); await writable.write(data); await writable.close();
}, bytes.toString('base64'));

try {
  const version = harness.version;
  await ctx.load();

  if (args["backend-version-fault"]) {
    await assert.rejects(ctx.connect(), /Unsupported SQLite3MC backend/);
    assert.deepEqual(await ctx.snapshot(), [], "backend rejection must not touch OPFS");
    ctx.checks.push("a mismatched cipher backend is rejected before opening OPFS");
  } else {
    let legacyGvk;
    if (args["legacy-db"]) {
      await ctx.injectLegacy(await readFile(args["legacy-db"]));
      if (args["legacy-gvk"]) {
        legacyGvk = JSON.parse(await readFile(args["legacy-gvk"], "utf8"));
        // The GVK private key must not stay readable anywhere once encrypted.
        ctx.secrets = [ctx.marker, legacyGvk.privateKey];
      }
      assert.equal(await ctx.connect(), "unencrypted");
      ctx.checks.push("an earlier unencrypted database is found");
    } else {
      assert.equal(await ctx.connect(), "new");
      ctx.checks.push("a fresh profile reports a new database");
    }

    assert.notEqual(await ctx.outcome("createWallet", WALLET_CONTEXT, "invalid"), "ok");
    assert.notEqual(await ctx.status(), "unlocked");
    assert.equal(await harness.page.evaluate(async () => (await storage.walletContext()) ?? null), null);
    assert(await harness.page.evaluate(() => ['create', 'unlock', 'enrollWallet', 'passkeyContext', 'unlockPasskey', 'changePassword', 'recoverPassword'].every(name => typeof storage[name] === 'undefined')));
    ctx.checks.push("invalid wallet secrets are rejected without records; password/passkey APIs are absent");

    await ctx.create();
    assert.equal(await ctx.status(), "unlocked");
    if (!args["legacy-db"]) {
      // Simulate an interrupted first setup: retain its envelope, remove only
      // the empty encrypted database, and resume with the same wallet context.
      await ctx.close();
      await harness.page.evaluate(async () => {
        const root = await navigator.storage.getDirectory();
        const opaque = await (await root.getDirectoryHandle('.opfs-sahpool-encrypted')).getDirectoryHandle('.opaque');
        for await (const [name, handle] of opaque.entries()) {
          const header = new TextDecoder().decode(await (await handle.getFile()).slice(0, 512).arrayBuffer()).split('\0')[0];
          if (header === 'spp.encrypted.db') await opaque.removeEntry(name);
        }
      });
      await ctx.load();
      assert.equal(await ctx.connect(), "locked");
      assert.notEqual(await ctx.outcome("createWallet", WALLET_CONTEXT, WALLET_SECRET), "ok");
      await ctx.unlock();
      assert.deepEqual(await harness.page.evaluate(() => storage.walletContext()), WALLET_CONTEXT);
      ctx.checks.push("interrupted setup resumes with its saved wallet key instead of replacing it");
    }
    await ctx.setMarker();
    assert.deepEqual(await harness.page.evaluate(() => storage.walletContext()), WALLET_CONTEXT);
    ctx.checks.push("wallet-only creation persists signing context and opens encrypted storage");
    if (args["legacy-db"]) {
      const snapshot = await ctx.snapshot();
      assert(!snapshot.some(file => file.path.startsWith(".opfs-sahpool/")), "the unencrypted pool is still there");
      assert(!snapshot.some(file => file.protected), "an unencrypted secret is still readable in OPFS");
      if (legacyGvk) {
        const stored = (await harness.page.evaluate(() => storage.call({ GetSetting: 'gvk_authority' }))).Setting;
        assert.equal(JSON.parse(stored).privateKey, legacyGvk.privateKey, "the GVK authority key did not survive");
      }
      ctx.checks.push("the unencrypted database is encrypted, then deleted with its pool");
    } else {
      ctx.checks.push("create opens a new encrypted database");
    }
    await ctx.close();

    // The app recognises a second tab by this exact message.
    await ctx.load();
    assert.equal(await ctx.connect(), "locked");
    const secondTab = await harness.context.newPage();
    await ctx.load(secondTab);
    await assert.rejects(secondTab.evaluate(() => sdk.Storage.connect()), /Another tab or window is using this app's local database/);
    await secondTab.close();
    ctx.checks.push("second tab reports the database lock");

    const locked = await ctx.snapshot();
    assert.notEqual(await ctx.outcome("unlockWallet", WALLET_CONTEXT, "cd".repeat(32)), "ok");
    assert.equal(await ctx.status(), "locked");
    assert.deepEqual(await ctx.snapshot(), locked, "a wrong wallet secret modified OPFS");
    ctx.checks.push("a wrong wallet secret is refused without modifying OPFS and can be retried");
    await ctx.unlock();
    assert(await ctx.marked());
    ctx.checks.push("unlock opens the database with its data");

    await ctx.close();

    await harness.restart();
    await ctx.load();
    assert.equal(await ctx.connect(), "locked");
    assert.notEqual(await ctx.outcome("unlockWallet", WALLET_CONTEXT, 'cd'.repeat(32)), "ok");
    assert.equal(await ctx.status(), "locked");
    assert.equal(await ctx.outcome("unlockWallet", WALLET_CONTEXT, WALLET_SECRET), "ok");
    assert(await ctx.marked());
    ctx.checks.push("wallet unlock survives browser-process restart; wrong secret stays locked");
    const final = await ctx.snapshot();
    assert(final.some(file => file.path.startsWith(".opfs-sahpool-encrypted/")));
    assert(!final.some(file => file.protected), "a protected value is readable in OPFS");
    ctx.checks.push("encrypted browser-process restart, and no protected value readable in OPFS");

    await harness.page.evaluate(() => storage.reset());
    assert.notEqual(await ctx.outcome("status"), "ok", "reset must close the old session");
    await ctx.load();
    await ctx.connect();
    assert.equal(await ctx.status(), "new");
    assert.equal(await harness.page.evaluate(async () => (await storage.walletContext()) ?? null), null);
    assert.notEqual(await ctx.outcome("unlockWallet", WALLET_CONTEXT, WALLET_SECRET), "ok");
    await ctx.create();
    assert(!(await ctx.marked()), "reset kept the old data");
    await ctx.close();
    ctx.checks.push("reset discards the database and a new wallet envelope starts over");
  }

  const result = { browser: args.browser, version, checks: ctx.checks, passed: true };
  await writeFile(join(artifacts, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} finally {
  await harness.close();
}

import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { build } from '../node_modules/esbuild/lib/main.js';

const { outputFiles } = await build({
    stdin: { contents: "export { ensureStorage, ensurePrivateStorage, isStorageUnlocked } from './js/wasm-facade.js';", resolveDir: new URL('../', import.meta.url).pathname },
    bundle: true, write: false, format: 'iife', globalName: 'facade',
    plugins: [{ name: 'sdk-fixture', setup(builder) {
        builder.onResolve({ filter: /^stellar-private-payments$/ }, () => ({ path: 'sdk', namespace: 'fixture' }));
        builder.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'wallet', namespace: 'fixture' }));
        builder.onLoad({ filter: /.*/, namespace: 'fixture' }, ({ path }) => ({ contents: path === 'wallet'
            ? 'export class FreighterSigner {}'
            : `export default async function init() {}
               export const Storage = { connect: async () => { if (globalThis.connectError) throw Error('OPFS unavailable'); return globalThis.nextStorage; } };
               export const Client = {}, DisclosureRequest = {}, bootnodeRequired = () => {},
                 deriveAspUserLeaf = () => {}, verifySelectiveDisclosure = () => {},
                 configureTelemetry = () => {}, dump_recent_logs = () => {}, debugLogsEnabled = () => false;` }));
    } }],
});

test('public startup does not unlock; failed private access retains public storage; BFCache restores reload', async () => {
    let reloads = 0; const timers = new Set();
    const window = Object.assign(new EventTarget(), {
        location: { href: 'https://storage.test/', reload() { reloads++; } },
        setInterval(fn) { timers.add(fn); return fn; },
        clearInterval(fn) { timers.delete(fn); },
    });
    const document = Object.assign(new EventTarget(), { baseURI: 'https://storage.test/' });
    const context = vm.createContext({ window, document, URL, Event, performance, setTimeout, clearTimeout, TextEncoder, TextDecoder, crypto: globalThis.crypto, console });
    const storage = status => ({
        closed: 0, freed: 0, paused: 0,
        async status() { if (status === 'error') throw Error('broken password record'); return status; },
        async close() { this.closed++; },
        free() { this.freed++; },
        async call(request) { assert.equal(request, 'Pause'); this.paused++; },
    });
    context.nextStorage = storage('error');
    context.connectError = true;
    vm.runInContext(outputFiles[0].text, context);
    await assert.rejects(context.facade.ensureStorage(), /OPFS unavailable/);
    context.connectError = false;
    await context.facade.ensureStorage();
    assert.equal(timers.size, 0, 'public access must not start a private session');
    assert.equal(context.facade.isStorageUnlocked(), false);
    await assert.rejects(context.facade.ensurePrivateStorage(), /broken password record/);
    assert.equal(context.nextStorage.closed, 0, 'public cache must remain usable after a failed unlock');
    assert.equal(context.nextStorage.freed, 0);
    await context.facade.ensureStorage();
    context.nextStorage.status = async () => 'unlocked';
    await Promise.all([context.facade.ensurePrivateStorage(), context.facade.ensurePrivateStorage()]);
    assert.equal(timers.size, 1);
    assert.equal(context.facade.isStorageUnlocked(), true);
    window.dispatchEvent(new Event('pagehide'));
    assert.equal(context.nextStorage.paused, 1);
    window.dispatchEvent(new Event('pageshow'));
    assert.equal(reloads, 0);
    const restored = new Event('pageshow');
    Object.defineProperty(restored, 'persisted', { value: true });
    window.dispatchEvent(restored);
    assert.equal(reloads, 1);
});

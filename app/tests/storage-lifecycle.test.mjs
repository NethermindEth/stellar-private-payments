import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { build } from '../node_modules/esbuild/lib/main.js';

const { outputFiles } = await build({
    stdin: { contents: "export { ensureStorage } from './js/wasm-facade.js';", resolveDir: new URL('../', import.meta.url).pathname },
    bundle: true, write: false, format: 'iife', globalName: 'facade',
    plugins: [{ name: 'sdk-fixture', setup(builder) {
        builder.onResolve({ filter: /^stellar-private-payments$/ }, () => ({ path: 'sdk', namespace: 'fixture' }));
        builder.onResolve({ filter: /^stellar-private-payments\/freighter$/ }, () => ({ path: 'wallet', namespace: 'fixture' }));
        builder.onLoad({ filter: /.*/, namespace: 'fixture' }, ({ path }) => ({ contents: path === 'wallet'
            ? 'export class FreighterSigner {}'
            : `export default async function init() {}
               export const Storage = { connect: async () => globalThis.nextStorage };
               export const Client = {}, DisclosureRequest = {}, bootnodeRequired = () => {},
                 deriveAspUserLeaf = () => {}, verifySelectiveDisclosure = () => {},
                 configureTelemetry = () => {}, dump_recent_logs = () => {}, debugLogsEnabled = () => false;` }));
    } }],
});

test('failed opening closes and frees its worker; retries own lifecycle hooks; BFCache restores reload', async () => {
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
    vm.runInContext(outputFiles[0].text, context);
    await assert.rejects(context.facade.ensureStorage(), /broken password record/);
    const failed = context.nextStorage;
    assert.equal(failed.closed, 1); assert.equal(failed.freed, 1);
    window.dispatchEvent(new Event('pagehide'));
    assert.equal(failed.paused, 0, 'failed worker must not retain lifecycle listeners');
    context.nextStorage = storage('unlocked');
    await context.facade.ensureStorage();
    assert.equal(timers.size, 1);
    window.dispatchEvent(new Event('pagehide'));
    assert.equal(context.nextStorage.paused, 1);
    window.dispatchEvent(new Event('pageshow'));
    assert.equal(reloads, 0);
    const restored = new Event('pageshow');
    Object.defineProperty(restored, 'persisted', { value: true });
    window.dispatchEvent(restored);
    assert.equal(reloads, 1);
});

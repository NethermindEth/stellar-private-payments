import assert from 'node:assert/strict';
import test from 'node:test';
import { startAutoLock, autoLockMinutes, setAutoLockMinutes, MAX_BUSY_LOCK_DELAY_MS } from '../../../app/js/storage-timeout.js';
import { closeAndReload } from '../../../app/js/storage-lock.js';

function fixture(t) {
    const previousWindow = globalThis.window;
    const previousDocument = globalThis.document;
    const previousNow = Date.now;
    let now = 0, tick, busy = false, locks = 0;
    const records = new Map();
    globalThis.window = new EventTarget();
    window.localStorage = { getItem: k => records.get(k) ?? null, setItem: (k, v) => records.set(k, v) };
    window.setInterval = fn => { tick = fn; return 1; };
    window.clearInterval = () => { tick = null; };
    globalThis.document = new EventTarget();
    document.querySelector = () => busy ? {} : null;
    Date.now = () => now;
    const stop = startAutoLock(() => locks++);
    t.after(() => { stop(); Date.now = previousNow; globalThis.window = previousWindow; globalThis.document = previousDocument; });
    return { advance: ms => { now += ms; }, tick: () => tick?.(), busy: value => { busy = value; }, locks: () => locks, stop };
}

test('defaults to five minutes, locks once, and removes listeners on stop', t => {
    const f = fixture(t);
    assert.equal(autoLockMinutes(), 5);
    f.advance(299999); f.tick(); assert.equal(f.locks(), 0);
    f.advance(1); f.tick(); f.tick(); assert.equal(f.locks(), 1);
    f.stop(); window.dispatchEvent(new Event('focus')); assert.equal(f.locks(), 1);
});
test('activity resets the deadline; returning to an expired tab locks immediately', t => {
    const f = fixture(t);
    f.advance(240000); window.dispatchEvent(new Event('pointerdown'));
    f.advance(240000); f.tick(); assert.equal(f.locks(), 0);
    f.advance(60000); document.dispatchEvent(new Event('visibilitychange'));
    assert.equal(f.locks(), 1);
});
test('timeout choices persist and Never disables the timeout', t => {
    const f = fixture(t);
    setAutoLockMinutes(15); assert.equal(autoLockMinutes(), 15);
    f.advance(300000); f.tick(); assert.equal(f.locks(), 0);
    setAutoLockMinutes(0); f.advance(3600000); f.tick(); assert.equal(f.locks(), 0);
    assert.throws(() => setAutoLockMinutes(-1));
    setAutoLockMinutes(5); f.tick(); assert.equal(f.locks(), 1);
});
test('an active transaction gets bounded grace, never an indefinite exemption', t => {
    const f = fixture(t);
    f.busy(true); f.advance(300000); f.tick(); assert.equal(f.locks(), 0);
    f.advance(MAX_BUSY_LOCK_DELAY_MS); f.tick(); assert.equal(f.locks(), 1);
});
test('lock reloads after successful close or failed close', async () => {
    for (const fail of [false, true]) {
        const events = [];
        await closeAndReload({ close: async () => { events.push('close'); if (fail) throw Error('closed'); } }, { reload: () => events.push('reload') });
        assert.deepEqual(events, ['close', 'reload']);
    }
});
test('an unresponsive worker cannot prevent locking', async () => {
    let reloads = 0;
    await closeAndReload({ close: () => new Promise(() => {}) }, { timeoutMs: 5, reload: () => reloads++ });
    assert.equal(reloads, 1);
});

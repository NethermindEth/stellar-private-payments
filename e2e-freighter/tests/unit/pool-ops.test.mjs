// Coverage for in-flight operation tracking.
//
// registerPublicKeys signs on-chain from two call sites — Settings and the
// wizard's registerNow — and both must be wrapped in beginPoolOp/endPoolOp, or
// the watcher drains without seeing them.
//
// pool-ops.js is dependency-free, unlike pool.js, which imports the wasm facade
// and cannot be loaded under plain `node --test`.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    beginPoolOp,
    endPoolOp,
    hasInFlightPoolOps,
    waitForPoolOpsToDrain,
} from '../../../app/js/pool-ops.js';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));

test('no op in flight initially', () => {
    assert.equal(hasInFlightPoolOps(), false);
});

test('beginPoolOp/endPoolOp pair correctly', () => {
    assert.equal(hasInFlightPoolOps(), false);
    beginPoolOp();
    assert.equal(hasInFlightPoolOps(), true);
    endPoolOp();
    assert.equal(hasInFlightPoolOps(), false);
});

test('overlapping ops are counted, not merely flagged', () => {
    beginPoolOp();
    beginPoolOp();
    assert.equal(hasInFlightPoolOps(), true);
    endPoolOp();
    assert.equal(hasInFlightPoolOps(), true, 'one op is still in flight');
    endPoolOp();
    assert.equal(hasInFlightPoolOps(), false);
});

test('an extra endPoolOp cannot make the counter negative or falsely drained-forever', () => {
    // Defensive: a bug elsewhere that calls endPoolOp twice must not corrupt
    // the counter into a state where a REAL future op is invisible.
    endPoolOp();
    endPoolOp();
    assert.equal(hasInFlightPoolOps(), false);
    beginPoolOp();
    assert.equal(hasInFlightPoolOps(), true, 'a genuine op after over-draining must still be visible');
    endPoolOp();
});

test('waitForPoolOpsToDrain resolves immediately when nothing is in flight', async () => {
    assert.equal(await waitForPoolOpsToDrain(), true);
});

test('waitForPoolOpsToDrain resolves once the in-flight op ends', async () => {
    beginPoolOp();
    const drained = waitForPoolOpsToDrain({ intervalMs: 5 });
    setTimeout(() => endPoolOp(), 20);
    assert.equal(await drained, true);
});

test('waitForPoolOpsToDrain times out rather than hanging forever', async () => {
    beginPoolOp();
    try {
        const result = await waitForPoolOpsToDrain({ timeoutMs: 30, intervalMs: 5 });
        assert.equal(result, false, 'must report failure, not resolve true, when the op never ends');
    } finally {
        endPoolOp();
    }
});

// --- both registration sites are wrapped ---------------------------------
// The tracker itself is fully behavioural; whether the two call sites
// actually use it is ordering/wiring, asserted over source the same way as
// the rebind windows and the facade's session-cache write.

const NAVIGATION = readFileSync(repoFile('app/js/ui/navigation.js'), 'utf8');
const WIZARD = readFileSync(repoFile('app/js/ui/onboarding-wizard.js'), 'utf8');

/**
 * Whether a `registerPublicKeys(` call lies between a beginPoolOp() and its
 * following endPoolOp(). Containment rather than a character window, so
 * intervening comments cannot break it.
 */
function callIsInsidePoolOpWrap(source, callNeedle) {
    let from = 0;
    for (;;) {
        const begin = source.indexOf('beginPoolOp()', from);
        if (begin === -1) return false;
        const end = source.indexOf('endPoolOp()', begin);
        if (end === -1) return false;
        const call = source.indexOf(callNeedle, begin);
        if (call !== -1 && call < end) return true;
        from = begin + 1;
    }
}

test('the Settings registration action is wrapped in beginPoolOp/endPoolOp', () => {
    assert.notEqual(
        NAVIGATION.indexOf('registerPublicKeys('), -1,
        'the Settings registration call must still exist',
    );
    assert.ok(
        callIsInsidePoolOpWrap(NAVIGATION, 'registerPublicKeys('),
        'registerPublicKeys signs and submits on-chain, exactly like the flows runPoolOp ' +
        'wraps in transactions.js -- without beginPoolOp, hasInFlightPoolOps() cannot see it, ' +
        'and the watcher can disconnect mid-signature',
    );
});

test('registerNow (onboarding wizard) is wrapped in beginPoolOp/endPoolOp', () => {
    const call = WIZARD.indexOf('registerPublicKeys(');
    assert.notEqual(call, -1, 'registerNow must still call registerPublicKeys');
    assert.ok(callIsInsidePoolOpWrap(WIZARD, 'registerPublicKeys('));
    const region = WIZARD.slice(Math.max(0, call - 400), call + 400);
    assert.match(region, /endPoolOp\(\)/);
});

// --- the watcher cannot be left permanently muted ------------------------

test('_pendingChange is reset even if disconnect() throws', () => {
    const setTrue = NAVIGATION.indexOf('this._pendingChange = true;');
    assert.notEqual(setTrue, -1, 'the guard must still be set before the teardown work');
    const tryStart = NAVIGATION.indexOf('try {', setTrue);
    const disconnectCall = NAVIGATION.indexOf('this.disconnect();', setTrue);
    const finallyReset = NAVIGATION.indexOf('this._pendingChange = false;', setTrue);
    assert.notEqual(tryStart, -1, 'the teardown must be inside a try block');
    assert.notEqual(disconnectCall, -1, 'this.disconnect() must still be called');
    assert.notEqual(finallyReset, -1, 'the guard must still be reset');
    assert.ok(
        tryStart < disconnectCall && disconnectCall < finallyReset,
        'disconnect() must run inside a try whose finally resets _pendingChange, so a throw ' +
        'cannot leave the guard permanently true and mute every later account/network change',
    );
    const finallyKeyword = NAVIGATION.lastIndexOf('finally', finallyReset);
    assert.ok(
        finallyKeyword !== -1 && disconnectCall < finallyKeyword && finallyKeyword < finallyReset,
        'the reset must specifically be in a finally block between the try and the reset, ' +
        'not merely somewhere later in the function',
    );
});

test('the watcher callback surfaces an async rejection, not only a sync throw', () => {
    const WALLET = readFileSync(repoFile('app/js/wallet.js'), 'utf8');
    // Anchored on the onChange INVOCATION rather than on `watcher.watch(`.
    // The original sliced forward from watcher.watch(, which broke the moment
    // the delivery closure was extracted into `deliver`, leaving
    // watcher.watch(deliver) as a one-liner -- the .catch( moved ABOVE the
    // anchor. The invariant under test is "the path that invokes onChange
    // surfaces an async rejection"; anchoring on that call site states it
    // directly and survives where the delivery closure is declared. The
    // assertions themselves are unchanged.
    assert.notEqual(WALLET.indexOf('watcher.watch('), -1, 'startWalletWatcher must still wrap watcher.watch');
    const invoke = WALLET.indexOf('onChange?.(info)');
    assert.notEqual(invoke, -1, 'startWalletWatcher must still invoke the onChange handler');
    const region = WALLET.slice(Math.max(0, invoke - 200), invoke + 300);
    assert.ok(
        !/try\s*\{\s*onChange\?\.\(info\)/.test(region),
        'a plain try/catch around a bare `onChange?.(info)` call only catches a throw before ' +
        'the handler\'s first await -- onChange is async, so a later rejection escaped invisibly',
    );
    assert.match(
        region,
        /\.catch\(/,
        'the async result of onChange must be handled with .catch (or awaited in a try/catch), ' +
        'so a rejection from anywhere in the handler is at least logged',
    );
});

// --- the op lifetime covers the history write -------------------------------

import {
    runTrackedOp,
    waitForPoolOpsToDrainNotified,
} from '../../../app/js/pool-ops.js';

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('runTrackedOp keeps the op in flight until a deferred write settles', async () => {
    const gate = deferred();
    const op = runTrackedOp(async () => {
        // Stands in for the OpHistory write after the pool operation.
        await gate.promise;
        return 'done';
    });
    await flush();
    assert.equal(
        hasInFlightPoolOps(),
        true,
        'the counter must not drain while the history write is still pending',
    );
    gate.resolve();
    assert.equal(await op, 'done');
    assert.equal(hasInFlightPoolOps(), false);
});

test('runTrackedOp ends the op even when the tracked work throws', async () => {
    await assert.rejects(
        runTrackedOp(async () => {
            throw new Error('pool op failed');
        }),
        /pool op failed/,
    );
    assert.equal(hasInFlightPoolOps(), false, 'a failed op must not wedge the drain');
});

test('runTrackedOp ends the op when an early stage succeeds but the write fails', async () => {
    // The history write failing must not leave the counter held either.
    await assert.rejects(
        runTrackedOp(async () => {
            await Promise.resolve('tx ok');
            throw new Error('record failed');
        }),
        /record failed/,
    );
    assert.equal(hasInFlightPoolOps(), false);
});

// --- a drain timeout is reported, not discarded -----------------------------

test('waitForPoolOpsToDrainNotified reports a timeout and still resolves false', async () => {
    const timeouts = [];
    beginPoolOp();
    try {
        const drained = await waitForPoolOpsToDrainNotified({
            timeoutMs: 30,
            intervalMs: 5,
            onTimeout: () => timeouts.push('reported'),
        });
        assert.equal(drained, false, 'the result must stay honest: the ops did not drain');
        assert.deepEqual(timeouts, ['reported'], 'a discarded timeout leaves no trace anywhere');
    } finally {
        endPoolOp();
    }
});

test('waitForPoolOpsToDrainNotified does not report when the ops drain', async () => {
    const timeouts = [];
    beginPoolOp();
    const drained = waitForPoolOpsToDrainNotified({
        intervalMs: 5,
        onTimeout: () => timeouts.push('reported'),
    });
    setTimeout(() => endPoolOp(), 20);
    assert.equal(await drained, true);
    assert.deepEqual(timeouts, []);
});

test('waitForPoolOpsToDrainNotified resolves immediately with nothing in flight', async () => {
    const timeouts = [];
    assert.equal(await waitForPoolOpsToDrainNotified({ onTimeout: () => timeouts.push('x') }), true);
    assert.deepEqual(timeouts, []);
});

// Behavioral coverage for app/js/onboarding-step-lifecycle.js. The wizard
// itself imports the wasm facade and does not load under `node --test`.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createStepLifecycle } from '../../../app/js/onboarding-step-lifecycle.js';

test('the step that just began owns the surface', () => {
    const l = createStepLifecycle();
    const token = l.begin();
    assert.equal(l.isLive(token), true);
    assert.equal(l.isCancelled(), false);
});

test('beginning the next step abandons the previous one', () => {
    const l = createStepLifecycle();
    const first = l.begin();
    const second = l.begin();
    assert.equal(l.isLive(first), false, 'an abandoned step must not still own the surface');
    assert.equal(l.isLive(second), true);
});

test('a settled step stops being live, so its own later awaits are dead', () => {
    const l = createStepLifecycle();
    const token = l.begin();
    l.retire(token);
    assert.equal(l.isLive(token), false);
});

test('retiring an already-abandoned step does not disturb the live one', () => {
    const l = createStepLifecycle();
    const first = l.begin();
    const second = l.begin();
    l.retire(first);
    assert.equal(l.isLive(second), true, 'a late retire from an old step must not deactivate the current one');
});

test('cancellation kills every step, including one still in flight', () => {
    const l = createStepLifecycle();
    const token = l.begin();
    l.cancel();
    assert.equal(l.isLive(token), false);
    assert.equal(l.isCancelled(), true);
});

test('a step begun after cancellation is still not live', () => {
    const l = createStepLifecycle();
    l.cancel();
    const token = l.begin();
    assert.equal(l.isLive(token), false, 'cancellation is terminal');
});

test('tokens are not reused, so a stale token never matches a later step', () => {
    const l = createStepLifecycle();
    const seen = new Set();
    for (let i = 0; i < 5; i += 1) seen.add(l.begin());
    assert.equal(seen.size, 5, 'each step must get a distinct token');
});

test('the abandoned-handler scenario end to end', async () => {
    const l = createStepLifecycle();
    const published = [];

    const stepA = l.begin();
    const handlerA = (async () => {
        await Promise.resolve();
        if (!l.isLive(stepA)) return;
        published.push('A');
    })();

    l.begin();
    await handlerA;

    assert.deepEqual(published, [], "an abandoned handler must not publish the previous account's keys");
});

test('a handler that is still live does publish', async () => {
    const l = createStepLifecycle();
    const published = [];

    const step = l.begin();
    await (async () => {
        await Promise.resolve();
        if (!l.isLive(step)) return;
        published.push('ok');
    })();

    assert.deepEqual(published, ['ok']);
});

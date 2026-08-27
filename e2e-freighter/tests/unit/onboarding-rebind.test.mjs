// Coverage for the wizard's rebind bookkeeping: which account the user is
// actually on, and which pending switch is still waiting to be acted on.
//
// Unlike rebind-windows.test.mjs these are behavioural rather than structural:
// app/js/onboarding-rebind.js imports nothing, so the state machine can be
// driven directly.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createRebindTracker } from '../../../app/js/onboarding-rebind.js';

const A = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const B = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ';
const C = 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCFFF';

test('a fresh tracker has the starting account current and nothing pending', () => {
    const rebind = createRebindTracker(A);
    assert.equal(rebind.current, A);
    assert.equal(rebind.pending, null);
    assert.equal(rebind.dueAddress(), null);
});

test('observing a different account arms the timer and records the switch', () => {
    const rebind = createRebindTracker(A);
    assert.equal(rebind.observe(B), 'arm');
    assert.equal(rebind.pending, B);
    assert.equal(rebind.dueAddress(), B);
});

test('observing the current account with nothing pending is ignored', () => {
    const rebind = createRebindTracker(A);
    assert.equal(rebind.observe(A), 'ignore');
    assert.equal(rebind.pending, null);
});

test('an absent address is ignored and disturbs nothing', () => {
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    for (const absent of [null, undefined, '']) {
        assert.equal(rebind.observe(absent), 'ignore');
        assert.equal(rebind.pending, B, 'a junk event must not clear a real pending switch');
    }
});

test('switching away and back cancels the pending switch and the timer', () => {
    // The defect: the listener returned early when the incoming address
    // equalled the current one, without clearing `pending` or the timer. The
    // timer then fired with the obsolete B and the wizard replanned for B
    // while the wallet was on A.
    const rebind = createRebindTracker(A);
    assert.equal(rebind.observe(B), 'arm');

    assert.equal(
        rebind.observe(A),
        'cancel',
        'returning to the current account must tell the caller to cancel its timer, ' +
        'not merely be ignored',
    );
    assert.equal(rebind.pending, null);
    assert.equal(
        rebind.dueAddress(),
        null,
        'a timer that fires anyway must find nothing due rather than the obsolete switch',
    );
});

test('a switch that is undone and redone is still pending', () => {
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    rebind.observe(A);
    assert.equal(rebind.observe(B), 'arm');
    assert.equal(rebind.dueAddress(), B, 'cancelling must not make the tracker deaf to a real switch');
});

test('discardStale keeps a genuine pending switch', () => {
    // The defect: the replan loop cleared `pending` unconditionally at its
    // top, after its own `await computeStepPlan(...)`. A switch arriving
    // during that await was therefore discarded.
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    rebind.discardStale();
    assert.equal(
        rebind.pending,
        B,
        'a pending switch to an account other than the current one is a real switch ' +
        'the user made, and must survive until it is adopted',
    );
});

test('discardStale drops only a pending value that is no longer a change', () => {
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    rebind.adopt();
    // Now current === B. A late event for B is stale, not a switch.
    rebind.observe(B);
    assert.equal(rebind.pending, null, 'observe already treats it as no change');
    rebind.discardStale();
    assert.equal(rebind.pending, null);
});

test('a second switch during a replan survives to be adopted next', () => {
    // The exact sequence the defect lost: A->B adopted and replanning, then
    // B->C arrives while computeStepPlan is awaiting, then the loop reaches
    // its bookkeeping.
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    assert.equal(rebind.adopt(), B);

    rebind.observe(C); // arrives during the replan's await
    assert.equal(rebind.dueAddress(), C, 'the loop must see C as still due');

    rebind.discardStale();
    assert.equal(rebind.adopt(), C, 'C must be adoptable on the next pass');
    assert.equal(rebind.current, C);
});

test('adopt makes the switch current and clears it', () => {
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    assert.equal(rebind.adopt(), B);
    assert.equal(rebind.current, B);
    assert.equal(rebind.pending, null);
    assert.equal(rebind.dueAddress(), null);
});

test('adopt reports no switch when there is nothing real to adopt', () => {
    const rebind = createRebindTracker(A);
    assert.equal(rebind.adopt(), null, 'nothing pending');

    rebind.observe(B);
    rebind.observe(A);
    assert.equal(rebind.adopt(), null, 'pending was undone');
    assert.equal(rebind.current, A, 'the current account must not move');
});

test('the tracker never reports the account it is already on as due', () => {
    // Guards the whole class of "replan for the account we are already on",
    // which would restart a step for no reason.
    const rebind = createRebindTracker(A);
    rebind.observe(B);
    rebind.adopt();
    assert.equal(rebind.current, B);
    assert.equal(rebind.observe(B), 'ignore');
    assert.equal(rebind.dueAddress(), null);
});

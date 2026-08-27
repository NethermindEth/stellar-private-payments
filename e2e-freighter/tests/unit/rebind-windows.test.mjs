// Ordering invariants for the two windows in which the wallet watcher can
// observe an account switch that nothing acts on.
//
// These assert over SOURCE, which needs justifying. Both properties are
// control-flow ordering — "the listener is registered before the first plan
// computation", "the epoch is re-checked after every await" — with no value to
// extract and assert on, and neither onboarding-wizard.js nor navigation.js
// loads under plain `node --test`. The e2e suite cannot reach these windows
// either: test 12 switches accounts at a fixed point after the wizard has
// subscribed.
//
// They cannot show the ordering is sufficient at runtime.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));

// Overridable so the same assertions can be run against another revision
// (see the header) without duplicating them.
const WIZARD = process.env.REBIND_WIZARD_SRC
  ? readFileSync(process.env.REBIND_WIZARD_SRC, 'utf8')
  : readFileSync(repoFile('app/js/ui/onboarding-wizard.js'), 'utf8');
const NAVIGATION = process.env.REBIND_NAV_SRC
  ? readFileSync(process.env.REBIND_NAV_SRC, 'utf8')
  : readFileSync(repoFile('app/js/ui/navigation.js'), 'utf8');

test('the wizard subscribes to wallet:account-rebind before it computes any plan', () => {
  const subscribe = WIZARD.indexOf("addEventListener('wallet:account-rebind'");
  assert.notEqual(subscribe, -1, 'the wizard must subscribe to wallet:account-rebind at all');

  // Call sites only -- the `async function computeStepPlan(` definition sits
  // near the top of the file and would otherwise always "precede" everything.
  const firstCall = WIZARD.indexOf('await computeStepPlan(');
  assert.notEqual(firstCall, -1, 'the wizard must compute a step plan');

  assert.ok(
    subscribe < firstCall,
    'computeStepPlan awaits six times, one of them a network recipientLookup. ' +
    'Computing a plan before subscribing means an account switch during that ' +
    'window is dispatched to nobody and lost, and the wizard then runs for the ' +
    'account the caller passed in rather than the one the user is on.',
  );
});

test('the wizard reconciles against live wallet state after subscribing', () => {
  // Subscribing first shrinks the window; it does not close it. The watcher
  // is started by navigation.js BEFORE the wizard is called, so a switch can
  // already have been dispatched into the void. The only way to recover it is
  // to re-read live state once the listener is attached.
  const subscribe = WIZARD.indexOf("addEventListener('wallet:account-rebind'");
  const reconcile = WIZARD.indexOf('App.state.wallet.address', subscribe);
  assert.notEqual(
    reconcile,
    -1,
    'after subscribing, the wizard must re-read App.state.wallet.address and treat a ' +
    'difference from the address it was passed as a pending rebind',
  );
});

test('the empty-plan exit cannot happen before the wizard has subscribed', () => {
  // The worst sub-case. If the "nothing to do" return runs while unsubscribed,
  // a switch in that window makes the wizard report "already onboarded" for
  // the OLD account; the caller then opens a session for the new one, so
  // onboarding is skipped entirely for an account that needed it.
  const subscribe = WIZARD.indexOf("addEventListener('wallet:account-rebind'");
  const emptyPlanExit = WIZARD.indexOf('hasRequiredStep(plan.steps)');
  assert.notEqual(emptyPlanExit, -1, 'the wizard must still short-circuit on an empty plan');
  assert.ok(
    subscribe < emptyPlanExit,
    'the empty-plan short-circuit must be reached with the rebind listener already attached',
  );
});

// Slice out connect()'s post-wizard hand-off: from the point the wizard has
// returned and a session starts being bound, to the point the app declares
// itself usable.
function handoffRegion(source) {
  const start = source.indexOf("walletState = 'binding'");
  const end = source.indexOf("walletState = 'ready'", start === -1 ? 0 : start);
  return { start, end, text: start === -1 || end === -1 ? '' : source.slice(start, end) };
}

test('a distinct post-wizard hand-off state exists', () => {
  const { start } = handoffRegion(NAVIGATION);
  assert.notEqual(
    start,
    -1,
    'connect() must mark the post-wizard hand-off with its own wallet state. While it ' +
    'was still "connecting", the watcher took its re-bind branch and mutated ' +
    'App.state.wallet.address while openAccount/userPublicKeys/loadRuntimeState/' +
    'createAppPool all ran against the address captured before them.',
  );
});

test('the watcher ends the session during the hand-off rather than re-binding', () => {
  const watcherBranch = NAVIGATION.indexOf("state === 'ready' || state === 'binding'");
  assert.notEqual(
    watcherBranch,
    -1,
    "the watcher's disconnect branch must cover the hand-off state as well as 'ready'; " +
    'during the hand-off there is no wizard on screen to re-point at another account',
  );
});

test('every await in the hand-off is followed by a supersession check', () => {
  const { text } = handoffRegion(NAVIGATION);
  assert.notEqual(text, '', 'hand-off region not found');

  const awaits = text.match(/\bawait\b/g)?.length ?? 0;
  const checks = text.match(/superseded\(\)/g)?.length ?? 0;

  assert.ok(awaits > 0, 'the hand-off is expected to await at least once');
  assert.ok(
    checks >= awaits,
    `the hand-off has ${awaits} await(s) but only ${checks} supersession check(s). ` +
    'Each await is a window in which the watcher can tear the session down; without a ' +
    'check after it, the remaining statements publish a session that no longer exists.',
  );
});

test('tearing the session down invalidates any connect() still in flight', () => {
  const disconnect = NAVIGATION.indexOf('    disconnect() {');
  assert.notEqual(disconnect, -1, 'disconnect() must exist');
  const body = NAVIGATION.slice(disconnect, disconnect + 600);
  assert.match(
    body,
    /_sessionEpoch\s*\+=\s*1/,
    'disconnect() must invalidate the in-flight connect(). A counter is required rather ' +
    'than re-reading walletState, because a fast disconnect-then-reconnect puts the state ' +
    'back to a value the stale connect() would accept.',
  );
});

// --- session-cache supersession ------------------------------------------
// createSessionGeneration's semantics are covered behaviourally in
// account-session-guard.test.mjs. What that cannot check is that the facade
// compares the token at the point of the cache WRITE rather than only before
// the call -- which is the whole defect, since checking before leaves the
// race exactly as it was. That placement is ordering again, so it is asserted
// here alongside the other ordering invariants.

const FACADE = process.env.REBIND_FACADE_SRC
  ? readFileSync(process.env.REBIND_FACADE_SRC, 'utf8')
  : readFileSync(repoFile('app/js/wasm-facade.js'), 'utf8');

test('the session cache write is guarded by a supersession check', () => {
  const await_ = FACADE.indexOf('await sdk.account(');
  assert.notEqual(await_, -1, 'openAccount must still call through to the SDK');

  const write = FACADE.indexOf('boundUserAddress = userAddress', await_);
  assert.notEqual(write, -1, 'openAccount must still populate the session cache');

  const check = FACADE.indexOf('isCurrent(', await_);
  assert.ok(
    check !== -1 && check < write,
    'the token must be compared after the await and before the cache is written. ' +
    'An abandoned openAccount keeps running after its caller has moved on; without ' +
    'a check at the write it resolves last and overwrites the session belonging to ' +
    'the account the user actually switched to.',
  );
});

test('tearing the client down invalidates in-flight opens', () => {
  const dispose = FACADE.indexOf('export function disposeClient');
  assert.notEqual(dispose, -1, 'disposeClient() must exist');
  const body = FACADE.slice(dispose, dispose + 800);
  assert.match(
    body,
    /invalidate\(\)/,
    'disposeClient() clears the session cache, so an open still in flight must be ' +
    'invalidated too or it will repopulate the cache moments after it was cleared',
  );
});

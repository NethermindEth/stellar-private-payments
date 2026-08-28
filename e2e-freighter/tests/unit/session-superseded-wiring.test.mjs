// Coverage for wiring a stale connect() attempt (and the two onboarding-wizard
// call sites) away from showing the raw SESSION_SUPERSEDED sentence or tearing
// down a session a newer flow already owns.
//
// navigation.js and onboarding-wizard.js both import wasm-facade.js, which
// imports the wasm package and cannot be loaded under plain `node --test` --
// the same constraint documented in pool-ops.test.mjs, so their wiring is
// asserted over source text instead.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));
const NAVIGATION = readFileSync(repoFile('app/js/ui/navigation.js'), 'utf8');
const WIZARD = readFileSync(repoFile('app/js/ui/onboarding-wizard.js'), 'utf8');
const TRANSACTIONS = readFileSync(repoFile('app/js/ui/transactions.js'), 'utf8');

test('a stale connect() attempt returns before disconnect() or any modal/toast', () => {
    const catchStart = NAVIGATION.indexOf('} catch (error) {');
    assert.notEqual(catchStart, -1);

    const supersededCheck = NAVIGATION.indexOf('if (superseded()) {', catchStart);
    assert.notEqual(supersededCheck, -1, 'the catch block must check superseded()');

    const earlyReturn = NAVIGATION.indexOf('return;', supersededCheck);
    const disconnectCall = NAVIGATION.indexOf('this.disconnect();', catchStart);
    assert.ok(
        supersededCheck < earlyReturn && earlyReturn < disconnectCall,
        'the stale-handler check must return before disconnect() runs, or a stale flow ' +
        'would tear down whatever newer flow superseded it',
    );
});

test("navigation.js's fallback toast uses friendlyErrorForCode, not the raw message", () => {
    assert.match(NAVIGATION, /import \{ friendlyErrorForCode \} from '\.\.\/facade-errors\.js';/);
    assert.match(NAVIGATION, /Toast\.show\(friendlyErrorForCode\(error\)/);
});

test('onboarding-wizard.js imports friendlyErrorForCode, not the raw message mapper', () => {
    assert.match(WIZARD, /import \{ friendlyErrorForCode \} from '\.\.\/facade-errors\.js';/);
    assert.doesNotMatch(WIZARD, /import \{ friendlyErrorMessage \}/);
});

test('the disclaimer-accept and derive-keys steps pass the caught error itself to setError, not just its message', () => {
    // Passing only error?.message would drop `.code`, and setError's friendly
    // mapping needs the code to distinguish SESSION_SUPERSEDED from a real
    // failure the user should see verbatim.
    const disclaimerCall = WIZARD.indexOf("setError(error || 'Failed to accept disclaimer')");
    const deriveCall = WIZARD.indexOf("setError(error || 'Failed to derive privacy keys')");
    assert.notEqual(disclaimerCall, -1, 'the disclaimer-accept step must pass the error object');
    assert.notEqual(deriveCall, -1, 'the derive-keys step must pass the error object');
});

test("setError funnels through friendlyErrorForCode, which is code-aware", () => {
    const fn = WIZARD.slice(WIZARD.indexOf('function setError'), WIZARD.indexOf('function showModal'));
    assert.match(fn, /friendlyErrorForCode\(errorOrMessage\)/);
});

test('the two openAccount-driven wizard steps still gate on isLive() before setError, so a stale step stays silent', () => {
    for (const anchor of [
        "setError(error || 'Failed to accept disclaimer')",
        "setError(error || 'Failed to derive privacy keys')",
    ]) {
        const call = WIZARD.indexOf(anchor);
        assert.notEqual(call, -1);
        const region = WIZARD.slice(Math.max(0, call - 200), call);
        assert.match(region, /if \(!isLive\(\)\) return;/, `expected an isLive() gate before: ${anchor}`);
    }
});

test('transactions.js forwards the app-level structured code alongside the SEP-0043 one', () => {
    assert.match(
        TRANSACTIONS,
        /code:\s*result\.code\s*\?\?\s*result\.errorCode/,
        'both result.code (SEP-0043) and result.errorCode (app-level) must reach ui/errors.js',
    );
});

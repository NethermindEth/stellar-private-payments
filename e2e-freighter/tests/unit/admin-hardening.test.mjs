// Source-level assertions over app/admin.html and app/js/admin.js.
//
// These assert PROPERTIES OF SOURCE, which needs justifying. app/js/admin.js
// imports './wasm-facade.js' (which loads the `stellar-private-payments` wasm
// package) and '@stellar/stellar-sdk', so the module cannot be loaded by a
// plain `node --test` process at all. The extractable logic lives in
// wallet-session-policy.js and wallet-signer-guard.js and is tested
// behaviourally in wallet-session-policy.test.mjs and pinned-signer.test.mjs.
// What remains here is what cannot be extracted: that admin.js actually WIRES
// those helpers up, on every path.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));

// Overridable so the same assertions can be run against another revision of
// these files without duplicating them.
const ADMIN_JS = readFileSync(process.env.ADMIN_JS_SRC || repoFile('app/js/admin.js'), 'utf8');
const ADMIN_HTML = readFileSync(process.env.ADMIN_HTML_SRC || repoFile('app/admin.html'), 'utf8');

/** Slice a top-level `async function name() { ... }` body out of the source. */
function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} must exist`);
    const end = source.indexOf('\n}\n', start);
    assert.notEqual(end, -1, `${signature} must be a top-level function`);
    return source.slice(start, end);
}

const countOf = (haystack, needle) => haystack.split(needle).length - 1;

// -----------------------------------------------------------------
// admin shares the hardened path instead of a second copy of it
// -----------------------------------------------------------------

test('admin observes the wallet through the shared watcher', () => {
    assert.match(
        ADMIN_JS,
        /startWalletWatcher/,
        'admin.js started no watcher at all, so an account or network switch after ' +
        'connect left it signing under one identity while the page named another.',
    );
    assert.match(
        ADMIN_JS,
        /createWalletSessionMonitor\(/,
        'change detection must be the shared rule, not a local copy',
    );
    assert.match(
        ADMIN_JS,
        /sessionUnverifiable/,
        'a wallet the watcher can no longer read must end the session, not be read as "no change"',
    );
});

test('admin applies the shared network guard, and applies it to every network read', () => {
    assert.match(ADMIN_JS, /requireTestnetNetwork/, 'admin.js had no network guard at all');

    // The property that matters is not "a guard exists somewhere" but that no
    // raw read escapes it. Both reads (refreshNetwork, requireWritableNetwork)
    // must be wrapped.
    const reads = countOf(ADMIN_JS, 'await getWalletNetwork()');
    const guarded = countOf(ADMIN_JS, 'requireTestnetNetwork(await getWalletNetwork())');
    assert.ok(reads > 0, 'admin.js must read the wallet network');
    assert.equal(
        guarded,
        reads,
        `${reads - guarded} of ${reads} getWalletNetwork() reads are not passed through ` +
        'requireTestnetNetwork; an unguarded read is how the page ended up trusting a ' +
        'network it never checked.',
    );
});

test('the guard is re-applied on the privileged write paths', () => {
    // A guard at connect time alone is not enough: the watcher polls every two
    // seconds, so anything switched between the last poll and the click is
    // still stale in `state` when the transaction is built. This
    // also covers the ACCOUNT, not just the network — see requireWritableSession.
    for (const fn of [
        'async function insertMembershipLeaf()',
        'async function insertNonMembershipLeaf()',
        'async function removeNonMembershipLeaf()',
        'async function toggleAdminInsertOnly()',
    ]) {
        assert.match(
            functionBody(ADMIN_JS, fn),
            /await requireWritableSession\(\)/,
            `${fn} submits a transaction and must re-check the wallet first`,
        );
    }
});

test('the hard-coded RPC fallback is gone', () => {
    // `state.rpcUrl = net.sorobanRpcUrl || 'https://soroban-testnet.stellar.org'`
    // produced a working testnet RPC client for a wallet that had reported no
    // endpoint -- so the page read state from one chain while the user signed
    // for another.
    assert.doesNotMatch(
        ADMIN_JS,
        /soroban-testnet\.stellar\.org/,
        'admin.js must take its RPC endpoint from the wallet or refuse, never substitute one',
    );
});

test('the signer identity is pinned rather than overridable', () => {
    assert.match(ADMIN_JS, /createPinnedSigner\(/, 'admin.js must pin its signing identity');
    assert.doesNotMatch(
        ADMIN_JS,
        /\.\.\.opts,/,
        'spreading the caller\'s opts last let contract.Client override the address ' +
        'verifySignerAddress compares against, so the guard validated the wrong pair',
    );
});

// ----------------------------------------------------
// the ASP secret is handled as a secret
// ----------------------------------------------------

test('the ASP secret field does not render in clear text', () => {
    const field = ADMIN_HTML.match(/<input[^>]*id="allowlistAspSecret"[^>]*>/);
    assert.ok(field, 'the ASP secret input must exist');
    assert.match(field[0], /type="password"/, 'the ASP secret must not be a plain text input');
    assert.doesNotMatch(field[0], /type="text"/);
});

// A forward-looking invariant: a future exit path must not be wired with its
// own inline clear that then drifts out of step with clearAspSecretInput().
test('only one place writes the secret field, so clearing cannot be partly wired', () => {
    assert.equal(
        countOf(ADMIN_JS, "allowlistAspSecretInput.value = ''"),
        1,
        'the field must be cleared through clearAspSecretInput() alone; a second inline ' +
        'assignment is how one exit path ends up clearing it and the others do not',
    );
});

test('the secret is cleared on failure, not only on success', () => {
    const body = functionBody(ADMIN_JS, 'async function insertMembershipLeaf()');
    const finallyAt = body.lastIndexOf('} finally {');
    assert.notEqual(finallyAt, -1, 'insertMembershipLeaf must have a finally block');
    assert.match(
        body.slice(finallyAt),
        /clearAspSecretInput\(\)/,
        'clearing only on the success path left the secret in the DOM after a validation ' +
        'error, a declined signature or an RPC failure',
    );
});

test('the secret is cleared on disconnect and on navigation away', () => {
    assert.match(
        functionBody(ADMIN_JS, 'function disconnect()'),
        /clearAspSecretInput\(\)/,
        'a disconnect must not leave the secret for whoever connects next',
    );
    assert.match(
        ADMIN_JS,
        /addEventListener\('pagehide',[\s\S]{0,120}clearAspSecretInput\(\)/,
        'pagehide covers navigation away and bfcache, where the DOM survives populated',
    );
});

test('no path logs or persists the secret', () => {
    assert.doesNotMatch(
        ADMIN_JS,
        /console\.[a-z]+\([^)]*aspSecret/i,
        'the secret must never reach the console',
    );
    const field = ADMIN_HTML.match(/<input[^>]*id="allowlistAspSecret"[^>]*>/)[0];
    assert.doesNotMatch(
        field,
        /autocomplete="(on|off)?"/,
        'autocomplete must be new-password so the browser neither saves nor refills it',
    );
    assert.match(field, /autocomplete="new-password"/);
});

test('the write guard re-confirms the account, not only the network', () => {
    const body = functionBody(ADMIN_JS, 'async function requireWritableSession()');
    assert.match(
        body,
        /getConnectedAddress\(\)/,
        'the write path must re-confirm the active account synchronously rather than trust the ' +
        'watcher, which can be blind for a bounded window',
    );
    assert.match(
        body,
        /active !== state\.address/,
        'a write must be refused when the wallet is on a different account than the page connected as',
    );
    assert.match(
        body,
        /if \(!active\)/,
        'getConnectedAddress() returns null when the origin is not granted — the exact ' +
        'condition — and a write must be refused, not attempted',
    );
});

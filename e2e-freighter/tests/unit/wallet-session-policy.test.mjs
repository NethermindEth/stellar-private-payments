// Coverage for app/js/wallet-session-policy.js.
//
// The module has no imports, so unlike wallet.js or admin.js it loads under a
// plain `node --test` process and its rules can be asserted directly.

import assert from 'node:assert/strict';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

// Overridable so the same assertions can be run against another revision of
// the module without duplicating them.
const {
    NO_RPC_MESSAGE,
    UNREADABLE_POLL_LIMIT,
    WRONG_NETWORK_MESSAGE,
    classifyWalletChange,
    createWalletSessionMonitor,
    requireTestnetNetwork,
} = await import(
    process.env.WALLET_POLICY_SRC
        ? pathToFileURL(process.env.WALLET_POLICY_SRC).href
        : '../../../app/js/wallet-session-policy.js'
);

const TESTNET = {
    network: 'TESTNET',
    networkPassphrase: 'Test SDF Network ; September 2015',
    sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
};

test('requireTestnetNetwork returns the network triple for a testnet wallet', () => {
    assert.deepEqual(requireTestnetNetwork(TESTNET), TESTNET);
});

test('requireTestnetNetwork rejects a non-testnet RPC endpoint', () => {
    assert.throws(
        () => requireTestnetNetwork({ ...TESTNET, sorobanRpcUrl: 'https://mainnet.sorobanrpc.com' }),
        { message: WRONG_NETWORK_MESSAGE },
    );
});

test('requireTestnetNetwork matches the endpoint case-insensitively', () => {
    // navigation.js lower-cased before testing; regressing to a case-sensitive
    // compare would lock out a wallet configured with a capitalised host.
    const upper = { ...TESTNET, sorobanRpcUrl: 'https://SOROBAN-TESTNET.stellar.org' };
    assert.equal(requireTestnetNetwork(upper).sorobanRpcUrl, upper.sorobanRpcUrl);
});

test('requireTestnetNetwork reports a missing RPC URL as its own condition', () => {
    // Not merely "it throws": navigation.js coerced a missing URL to '' and
    // let it fail the substring test, so a wallet that reported no Soroban
    // endpoint at all was told it was on the wrong network. The two are
    // different problems with different fixes.
    for (const missing of [undefined, null, '', '   ']) {
        assert.throws(
            () => requireTestnetNetwork({ ...TESTNET, sorobanRpcUrl: missing }),
            { message: NO_RPC_MESSAGE },
            `sorobanRpcUrl=${JSON.stringify(missing)} must report the missing-RPC condition`,
        );
    }
    assert.throws(() => requireTestnetNetwork(undefined), { message: NO_RPC_MESSAGE });
});

test('requireTestnetNetwork never substitutes a default endpoint', () => {
    // admin.js used to fall back to a hard-coded https://soroban-testnet...
    // when the wallet reported nothing, which produced a working testnet RPC
    // client for a wallet that was not necessarily on testnet.
    assert.throws(() => requireTestnetNetwork({ network: 'PUBLIC' }), (err) => {
        assert.doesNotMatch(err.message, /soroban-testnet\.stellar\.org/);
        return true;
    });
});

const CURRENT = {
    address: 'GAAA',
    network: 'TESTNET',
    networkPassphrase: 'Test SDF Network ; September 2015',
};

test('classifyWalletChange reports no change when nothing moved', () => {
    assert.deepEqual(classifyWalletChange({ ...CURRENT }, CURRENT), {
        unreadable: false,
        networkChanged: false,
        addressChanged: false,
        changed: false,
    });
});

test('classifyWalletChange treats a missing notification as no evidence', () => {
    // No callback at all says nothing about the wallet either way, so it must
    // not count toward the unreadable streak.
    for (const info of [null, undefined]) {
        assert.deepEqual(classifyWalletChange(info, CURRENT), {
            unreadable: false,
            networkChanged: false,
            addressChanged: false,
            changed: false,
        });
    }
});

test('classifyWalletChange reports an unreadable wallet rather than "no change"', () => {
    // Classifying `{error}` as changed:false would leave a page connected
    // under the previous identity after the user switched to an account that
    // had not granted this origin.
    const errored = classifyWalletChange({ error: 'boom', address: '' }, CURRENT);
    assert.equal(errored.unreadable, true);
    assert.equal(errored.changed, false, 'an unreadable wallet is not a *change* — it is an unknown');
});

test('classifyWalletChange treats a missing address as unreadable, error payload or not', () => {
    // Load-bearing for the streak below. Freighter's WatchWalletChanges.fetchInfo
    // has no `return` after its error callback, so a failed poll fires a SECOND
    // callback that carries no error field and `address: undefined`. Keying
    // "unreadable" on info.error alone would classify that second callback as a
    // healthy poll.
    for (const info of [
        { address: undefined, network: undefined, networkPassphrase: undefined },
        { address: '', network: '', networkPassphrase: '' },
        {},
    ]) {
        assert.equal(
            classifyWalletChange(info, CURRENT).unreadable,
            true,
            `${JSON.stringify(info)} names no active account and must count as unreadable`,
        );
    }
});

test('classifyWalletChange treats fields the watcher omitted as unchanged', () => {
    // Freighter's watcher omits what it has not observed yet. Reading absent
    // as "changed to undefined" would tear down a healthy session on the very
    // first poll.
    assert.equal(classifyWalletChange({}, CURRENT).changed, false);
    assert.equal(classifyWalletChange({ address: CURRENT.address }, CURRENT).changed, false);
});

test('classifyWalletChange detects an account switch', () => {
    const result = classifyWalletChange({ ...CURRENT, address: 'GBBB' }, CURRENT);
    assert.deepEqual(result, { unreadable: false, networkChanged: false, addressChanged: true, changed: true });
});

test('classifyWalletChange detects a network switch with the account unchanged', () => {
    // Comparing the address alone misses a network switch,
    // and a transaction built for one passphrase and signed under another is
    // exactly what the watcher exists to catch.
    const byName = classifyWalletChange({ ...CURRENT, network: 'PUBLIC' }, CURRENT);
    assert.deepEqual(byName, { unreadable: false, networkChanged: true, addressChanged: false, changed: true });

    const byPassphrase = classifyWalletChange(
        { ...CURRENT, networkPassphrase: 'Public Global Stellar Network ; September 2015' },
        CURRENT,
    );
    assert.equal(byPassphrase.networkChanged, true);
});

test('classifyWalletChange reports both when both moved', () => {
    const result = classifyWalletChange({ address: 'GBBB', network: 'PUBLIC' }, CURRENT);
    assert.deepEqual(result, { unreadable: false, networkChanged: true, addressChanged: true, changed: true });
});

// ── createWalletSessionMonitor: the streak policy ───────────────────────────

const ERROR_POLL = { address: '', network: '', networkPassphrase: '', error: { message: 'not allowed' } };
const FALLTHROUGH_POLL = { address: undefined, network: undefined, networkPassphrase: undefined };

test('a single unreadable poll does not end the session', () => {
    // Freighter's background service worker sleeps and can fail one round
    // trip. Ending a healthy session on one blip would be a worse bug than
    // the one this fixes.
    const monitor = createWalletSessionMonitor();
    const first = monitor.observe(ERROR_POLL, CURRENT);
    assert.equal(first.unreadable, true);
    assert.equal(first.sessionUnverifiable, false);
    assert.equal(first.unreadableStreak, 1);
});

test('a persistently unreadable wallet ends the session at the limit', () => {
    const monitor = createWalletSessionMonitor({ unreadableLimit: 3 });
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, false);
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, false);
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, true);
});

test('the upstream double-callback must not reset the streak (regression)', () => {
    // THE regression this fix turns on. WatchWalletChanges.fetchInfo lacks a
    // `return` after its error callback, so ONE failed poll delivers
    // {error} and then {address: undefined}. A rule keyed on info.error would
    // score the second callback as a healthy poll, reset the counter, and the
    // limit would never be reached no matter how long the wallet stayed
    // unreadable — leaving the page live under the previous identity forever.
    const monitor = createWalletSessionMonitor({ unreadableLimit: 3 });

    assert.equal(monitor.observe(ERROR_POLL, CURRENT).unreadableStreak, 1);
    assert.equal(
        monitor.observe(FALLTHROUGH_POLL, CURRENT).unreadableStreak,
        2,
        'the fallthrough callback carries no error field and must still count as unreadable',
    );
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, true);
});

test('any readable poll clears the streak', () => {
    const monitor = createWalletSessionMonitor({ unreadableLimit: 3 });
    monitor.observe(ERROR_POLL, CURRENT);
    monitor.observe(ERROR_POLL, CURRENT);
    const recovered = monitor.observe({ ...CURRENT }, CURRENT);
    assert.equal(recovered.unreadableStreak, 0);
    assert.equal(recovered.sessionUnverifiable, false);
    // ...and the count really restarts, rather than resuming at 2.
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, false);
});

test('a readable poll that reports a change also clears the streak', () => {
    const monitor = createWalletSessionMonitor({ unreadableLimit: 3 });
    monitor.observe(ERROR_POLL, CURRENT);
    const changed = monitor.observe({ ...CURRENT, address: 'GBBB' }, CURRENT);
    assert.equal(changed.changed, true);
    assert.equal(changed.unreadableStreak, 0, 'a monitor must not carry a stale count into the next session');
});

test('reset() forgets the streak', () => {
    const monitor = createWalletSessionMonitor({ unreadableLimit: 2 });
    monitor.observe(ERROR_POLL, CURRENT);
    monitor.reset();
    assert.equal(monitor.observe(ERROR_POLL, CURRENT).sessionUnverifiable, false);
});

test('the shipped limit is a bounded window, not a placeholder', () => {
    // At the watcher's 2s poll interval this is ~6s of the page offering
    // actions under an identity it cannot confirm. Documented so a change to
    // it is a deliberate decision rather than a silent one.
    assert.ok(UNREADABLE_POLL_LIMIT >= 2, 'one poll would end healthy sessions on a transient blip');
    assert.ok(UNREADABLE_POLL_LIMIT <= 5, 'a long streak leaves the unverified window open too long');
});

// Unit coverage for app/js/account-session-guard.js. wasm-facade.js imports the
// wasm package and cannot be loaded under plain `node --test`, so the rules live
// here instead.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
    requireNoteOwner,
    sessionMatchesCache,
    createSessionGeneration,
    openPairKey,
    createInFlightOpenRegistry,
} from '../../../app/js/account-session-guard.js';

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const DELEGATE = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ';

test('requireNoteOwner returns the address when one is named', () => {
    assert.equal(requireNoteOwner(OWNER), OWNER);
});

for (const [label, value] of [
    ['undefined', undefined],
    ['null', null],
    ['an empty string', ''],
]) {
    test(`requireNoteOwner refuses ${label}`, () => {
        assert.throws(
            () => requireNoteOwner(value),
            (error) => {
                // The message must say what was refused and why, because this
                // surfaces to a developer, not an end user.
                assert.match(error.message, /userAddress/);
                return true;
            },
        );
    });
}

test('sessionMatchesCache reuses a session only when both identities match', () => {
    const cached = { userAddress: OWNER, signerAddress: OWNER };
    assert.equal(sessionMatchesCache(cached, { userAddress: OWNER, signerAddress: OWNER }), true);
});

test('sessionMatchesCache refuses a session bound to a different note owner', () => {
    const cached = { userAddress: OWNER, signerAddress: OWNER };
    assert.equal(
        sessionMatchesCache(cached, { userAddress: DELEGATE, signerAddress: DELEGATE }),
        false,
    );
});

test('sessionMatchesCache refuses a session bound to a different signer', () => {
    // Same note owner, different signing account: the pre-5.3 cache keyed on
    // both already covered this, and the extracted predicate must keep it.
    const cached = { userAddress: OWNER, signerAddress: OWNER };
    assert.equal(
        sessionMatchesCache(cached, { userAddress: OWNER, signerAddress: DELEGATE }),
        false,
    );
});

test('a null cache key never matches, not even another null', () => {
    // Without this, `null === null` made an unqualified request hit
    // an unqualified cache entry, handing back whichever account the wallet
    // was on when the entry was written.
    for (const absent of [null, undefined, '']) {
        assert.equal(
            sessionMatchesCache(
                { userAddress: absent, signerAddress: absent },
                { userAddress: absent, signerAddress: absent },
            ),
            false,
            `a cache entry keyed on ${JSON.stringify(absent)} must never be reusable`,
        );
    }
});

test('a half-populated cache entry never matches', () => {
    assert.equal(
        sessionMatchesCache(
            { userAddress: OWNER, signerAddress: null },
            { userAddress: OWNER, signerAddress: null },
        ),
        false,
    );
    assert.equal(
        sessionMatchesCache(
            { userAddress: null, signerAddress: OWNER },
            { userAddress: null, signerAddress: OWNER },
        ),
        false,
    );
});

// --- supersession of in-flight session opens -----------------------------
//
// The defect: rejecting the wizard's waitForStep promise does not cancel the
// async click handler behind it. Its openAccount call keeps running and, if
// it resolved after the replanned one, overwrote boundAccount/boundUserAddress
// in wasm-facade.js -- which had no guard at all.

test('a token is current until something newer claims one', () => {
    const gen = createSessionGeneration();
    const token = gen.begin();
    assert.equal(gen.isCurrent(token), true);
});

test('a newer open supersedes one still in flight', () => {
    const gen = createSessionGeneration();
    const abandoned = gen.begin();
    const replacement = gen.begin();
    assert.equal(
        gen.isCurrent(abandoned),
        false,
        'the abandoned open must not be allowed to write its result',
    );
    assert.equal(gen.isCurrent(replacement), true);
});

test('two opens for the same account still supersede each other', () => {
    // Why a counter and not an address comparison: the wizard can abandon an
    // open for account B and immediately start another for B, and the first
    // must still lose.
    const gen = createSessionGeneration();
    const first = gen.begin();
    const second = gen.begin();
    assert.equal(gen.isCurrent(first), false);
    assert.equal(gen.isCurrent(second), true);
});

test('a teardown supersedes everything in flight', () => {
    // disposeClient() clears the cache; without this an open still running
    // would repopulate it moments later.
    const gen = createSessionGeneration();
    const inFlight = gen.begin();
    gen.invalidate();
    assert.equal(gen.isCurrent(inFlight), false);
});

test('an open started after a teardown is current again', () => {
    const gen = createSessionGeneration();
    gen.begin();
    gen.invalidate();
    const fresh = gen.begin();
    assert.equal(gen.isCurrent(fresh), true, 'teardown must not poison the generation permanently');
});

test('a token never issued is not current', () => {
    const gen = createSessionGeneration();
    gen.begin();
    assert.equal(gen.isCurrent(0), false);
    assert.equal(gen.isCurrent(undefined), false);
    assert.equal(gen.isCurrent(99), false);
});

// --- coalescing concurrent opens of the same pair --------------------------

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

test('openPairKey keys on both identities', () => {
    assert.equal(openPairKey(OWNER, OWNER), openPairKey(OWNER, OWNER));
    assert.notEqual(openPairKey(OWNER, OWNER), openPairKey(OWNER, DELEGATE));
    assert.notEqual(openPairKey(OWNER, OWNER), openPairKey(DELEGATE, OWNER));
});

test('openPairKey is null when either identity is absent', () => {
    for (const absent of [null, undefined, '']) {
        assert.equal(openPairKey(absent, OWNER), null);
        assert.equal(openPairKey(OWNER, absent), null);
        assert.equal(openPairKey(absent, absent), null);
    }
});

test('concurrent opens of the same pair share one SDK call', async () => {
    const registry = createInFlightOpenRegistry();
    const gate = deferred();
    let opens = 0;
    const openFn = () => {
        opens += 1;
        return gate.promise;
    };

    const key = openPairKey(OWNER, OWNER);
    const first = registry.share(key, openFn);
    const second = registry.share(key, openFn);
    gate.resolve('account');

    assert.equal(await first, 'account');
    assert.equal(await second, 'account');
    assert.equal(opens, 1, 'the second caller must reuse the in-flight open, not open again');
});

test('concurrent opens of distinct pairs each reach the SDK', async () => {
    const registry = createInFlightOpenRegistry();
    const gateA = deferred();
    const gateB = deferred();
    const seen = [];

    const a = registry.share(openPairKey(OWNER, OWNER), () => {
        seen.push('a');
        return gateA.promise;
    });
    const b = registry.share(openPairKey(DELEGATE, DELEGATE), () => {
        seen.push('b');
        return gateB.promise;
    });
    gateB.resolve('B');
    gateA.resolve('A');

    assert.equal(await a, 'A');
    assert.equal(await b, 'B');
    assert.deepEqual(seen.sort(), ['a', 'b']);
});

test('a null key never coalesces', async () => {
    const registry = createInFlightOpenRegistry();
    const gate = deferred();
    let opens = 0;
    const first = registry.share(null, () => {
        opens += 1;
        return gate.promise.then(() => 'one');
    });
    const second = registry.share(null, () => {
        opens += 1;
        return gate.promise.then(() => 'two');
    });
    gate.resolve();

    assert.equal(await first, 'one');
    assert.equal(await second, 'two');
    assert.equal(opens, 2);
});

test('once the open settles, the next open of the pair starts fresh', async () => {
    const registry = createInFlightOpenRegistry();
    const key = openPairKey(OWNER, OWNER);
    let opens = 0;
    const openFn = () => Promise.resolve(`session-${(opens += 1)}`);

    assert.equal(await registry.share(key, openFn), 'session-1');
    assert.equal(
        await registry.share(key, openFn),
        'session-2',
        'a settled open is no longer in flight; the settled-session cache, not this registry, dedupes it',
    );
});

test('a rejected open rejects every waiter and clears the entry', async () => {
    const registry = createInFlightOpenRegistry();
    const gate = deferred();
    let opens = 0;
    const key = openPairKey(OWNER, OWNER);

    const first = registry.share(key, () => {
        opens += 1;
        return gate.promise;
    });
    const second = registry.share(key, () => {
        opens += 1;
        return gate.promise;
    });
    gate.reject(new Error('sdk unavailable'));

    await assert.rejects(first, /sdk unavailable/);
    await assert.rejects(second, /sdk unavailable/);
    assert.equal(opens, 1);

    // The failure must not pin the pair: a later open retries the SDK.
    const retry = registry.share(key, () => Promise.resolve('recovered'));
    assert.equal(await retry, 'recovered');
});

test('clear() drops in-flight entries so the next share opens anew', async () => {
    const registry = createInFlightOpenRegistry();
    const gate = deferred();
    let opens = 0;
    const key = openPairKey(OWNER, OWNER);
    const openFn = () => {
        opens += 1;
        const label = `open-${opens}`;
        return gate.promise.then(() => label);
    };

    const first = registry.share(key, openFn);
    registry.clear();
    const second = registry.share(key, openFn);
    gate.resolve();

    assert.equal(await first, 'open-1');
    assert.equal(await second, 'open-2');
    assert.equal(opens, 2, 'after a teardown a same-pair open must not join the pre-teardown one');
});

test('a late-resolving open does not evict a newer entry for the same pair', async () => {
    const registry = createInFlightOpenRegistry();
    const gateA = deferred();
    const gateB = deferred();
    const key = openPairKey(OWNER, OWNER);

    const first = registry.share(key, () => gateA.promise.then(() => 'stale'));
    registry.clear();
    let opensB = 0;
    const second = registry.share(key, () => {
        opensB += 1;
        return gateB.promise.then(() => 'fresh');
    });
    gateA.resolve();
    assert.equal(await first, 'stale');

    const third = registry.share(key, () => Promise.resolve('third'));
    gateB.resolve();
    assert.equal(await second, 'fresh');
    assert.equal(await third, 'fresh', 'a same-pair open must join the fresh in-flight one, not reopen');
    assert.equal(opensB, 1);
});

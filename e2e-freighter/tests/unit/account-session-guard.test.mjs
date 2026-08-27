// Unit coverage for app/js/account-session-guard.js. wasm-facade.js imports the
// wasm package and cannot be loaded under plain `node --test`, so the rules live
// here instead.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
    requireNoteOwner,
    sessionMatchesCache,
    createSessionGeneration,
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

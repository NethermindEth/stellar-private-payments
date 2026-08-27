// Coverage for createPinnedSigner in app/js/wallet-signer-guard.js.
//
// The defect it replaces was subtle: admin.js's signer closures spread the
// caller's `opts` LAST, so @stellar/stellar-sdk's contract.Client could
// override the `address` that verifySignerAddress compares against. The guard
// still ran and still passed -- against the wrong pair. These tests assert the
// override cannot happen, which is a property no amount of reading the call
// site makes obvious.

import assert from 'node:assert/strict';
import test from 'node:test';
import { createPinnedSigner, verifySignerAddress } from '../../../app/js/wallet-signer-guard.js';

const IDENTITY = { address: 'GADMIN', networkPassphrase: 'Test SDF Network ; September 2015' };

function recordingAdapter() {
    const calls = [];
    return {
        calls,
        signTransaction: async (xdr, opts) => { calls.push(['tx', xdr, opts]); return { signedTxXdr: 'S' }; },
        signAuthEntry: async (xdr, opts) => { calls.push(['auth', xdr, opts]); return { signedAuthEntry: 'S' }; },
    };
}

test('createPinnedSigner forwards the payload and the pinned identity', async () => {
    const adapter = recordingAdapter();
    const signer = createPinnedSigner(adapter, IDENTITY);

    await signer.signTransaction('XDR');
    await signer.signAuthEntry('ENTRY');

    assert.deepEqual(adapter.calls[0], ['tx', 'XDR', { ...IDENTITY }]);
    assert.deepEqual(adapter.calls[1], ['auth', 'ENTRY', { ...IDENTITY }]);
});

test('a caller cannot override the pinned address', async () => {
    // The regression. Before the pin, this call reached the wallet asking for
    // GATTACKER and verifySignerAddress happily confirmed the wallet signed as
    // GATTACKER -- while the admin page believed it was acting as GADMIN.
    const adapter = recordingAdapter();
    const signer = createPinnedSigner(adapter, IDENTITY);

    await signer.signTransaction('XDR', { address: 'GATTACKER' });
    await signer.signAuthEntry('ENTRY', { address: 'GATTACKER' });

    assert.equal(adapter.calls[0][2].address, 'GADMIN');
    assert.equal(adapter.calls[1][2].address, 'GADMIN');
});

test('a caller cannot override the pinned network passphrase', async () => {
    const adapter = recordingAdapter();
    const signer = createPinnedSigner(adapter, IDENTITY);

    await signer.signTransaction('XDR', { networkPassphrase: 'Public Global Stellar Network ; September 2015' });

    assert.equal(adapter.calls[0][2].networkPassphrase, IDENTITY.networkPassphrase);
});

test('unrelated caller options still pass through', async () => {
    // Pinning must not amount to discarding opts: contract.Client passes
    // submit/submitUrl through this same channel.
    const adapter = recordingAdapter();
    const signer = createPinnedSigner(adapter, IDENTITY);

    await signer.signTransaction('XDR', { submit: true, submitUrl: 'https://rpc.example' });

    assert.equal(adapter.calls[0][2].submit, true);
    assert.equal(adapter.calls[0][2].submitUrl, 'https://rpc.example');
    assert.equal(adapter.calls[0][2].address, 'GADMIN');
});

test('the pinned signer works when called as a bare unbound function', async () => {
    // contract.Client.from() invokes these options
    // as bare function calls, not methods. Anything relying on `this` throws
    // there, which is why this is not a class.
    const adapter = recordingAdapter();
    const { signTransaction, signAuthEntry } = createPinnedSigner(adapter, IDENTITY);

    await signTransaction('XDR');
    await signAuthEntry('ENTRY');

    assert.equal(adapter.calls.length, 2);
    assert.equal(adapter.calls[0][2].address, 'GADMIN');
});

test('createPinnedSigner refuses a partial identity', () => {
    // Pinning `address: undefined` would silently disarm verifySignerAddress,
    // which skips when it has no requested address to compare -- strictly
    // worse than the unpinned closure this replaces.
    for (const identity of [undefined, {}, { address: 'GADMIN' }, { networkPassphrase: 'p' }]) {
        assert.throws(
            () => createPinnedSigner(recordingAdapter(), identity),
            /requires both address and networkPassphrase/,
            `identity=${JSON.stringify(identity)} must be refused`,
        );
    }
});

test('the pin is what makes verifySignerAddress meaningful', async () => {
    // End-to-end over the two functions together: a wallet that signs with a
    // different account must be caught, and the comparison must be against the
    // PINNED address rather than whatever the caller asked for.
    const wallet = {
        signTransaction: async (xdr, opts) => {
            const signerAddress = 'GOTHER';
            verifySignerAddress('Transaction signature', opts.address, signerAddress);
            return { signedTxXdr: 'S', signerAddress };
        },
        signAuthEntry: async () => ({}),
    };
    const signer = createPinnedSigner(wallet, IDENTITY);

    // The caller claims the wallet's own account; without the pin this would
    // pass, because opts.address would equal signerAddress.
    await assert.rejects(
        () => signer.signTransaction('XDR', { address: 'GOTHER' }),
        { code: 'SIGNER_ADDRESS_MISMATCH' },
    );
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, hash } from '@stellar/stellar-sdk';
import { createFreighter, unlockFreighter } from '../js/storage-freighter.js';

const origin = 'https://storage.test';
function fixture() {
    const key = Keypair.random();
    const calls = [];
    const state = { fault: null, context: null, secret: null, unlocked: false };
    const signer = {
        async getPublicKey() { return state.fault === 'account' ? Keypair.random().publicKey() : key.publicKey(); },
        async signMessage(message, options) {
            calls.push({ message, options });
            if (state.fault === 'cancel' || (state.fault === 'cancel-second' && calls.length === 2)) throw Error('User declined');
            const signature = Buffer.from(key.sign(hash(Buffer.from(`Stellar Signed Message:\n${message}`))));
            if (state.fault === 'signature') signature[0] ^= 1;
            return {
                signedMessage: signature.toString(state.fault === 'hex' ? 'hex' : 'base64'),
                signerAddress: state.fault === 'reported-account' ? Keypair.random().publicKey() : key.publicKey(),
            };
        },
    };
    const storage = {
        async walletContext() { return structuredClone(state.context); },
        async createWallet(context, secret) {
            state.context = structuredClone(context); state.secret = secret;
        },
        async unlockWallet(context, secret) {
            assert.deepEqual(context, state.context); assert.equal(secret, state.secret); state.unlocked = true;
        },
    };
    return { signer, storage, state, calls };
}

test('enrollment checks repeatable signatures; a later unlock supports base64 and hex', async () => {
    const f = fixture();
    await createFreighter(f.storage, f.signer, origin);
    assert.equal(f.calls.length, 2);
    assert.deepEqual(f.calls[0], f.calls[1]);
    assert.match(f.calls[0].message, /Domain: spp\/database-key-wrap\/v1\/wallet-signature/);
    assert.match(f.calls[0].message, /Origin: https:\/\/storage.test/);
    assert.match(f.state.secret, /^[a-f0-9]{64}$/);
    await unlockFreighter(f.storage, f.signer, origin);
    f.state.fault = 'hex';
    await unlockFreighter(f.storage, f.signer, origin);
    assert.equal(f.state.unlocked, true);
});

for (const fault of ['reported-account', 'signature', 'cancel', 'cancel-second']) {
    test(`enrollment failure (${fault}) never persists access`, async () => {
        const f = fixture(); f.state.fault = fault;
        await assert.rejects(createFreighter(f.storage, f.signer, origin));
        assert.equal(f.state.context, null);
    });
}

test('wrong account, origin, invalid signature and cancellation cannot unlock', async () => {
    const f = fixture();
    await createFreighter(f.storage, f.signer, origin);
    for (const fault of ['account', 'reported-account', 'signature', 'cancel']) {
        f.state.fault = fault;
        await assert.rejects(unlockFreighter(f.storage, f.signer, origin));
        assert.equal(f.state.unlocked, false);
    }
    f.state.fault = null;
    await assert.rejects(unlockFreighter(f.storage, f.signer, 'https://other.test'));
    assert.equal(f.state.unlocked, false);
    await unlockFreighter(f.storage, f.signer, origin);
});

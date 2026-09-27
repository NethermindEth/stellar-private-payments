import test from 'node:test';
import assert from 'node:assert/strict';
import { enrollPasskey, unlockPasskey } from '../js/storage-passkey.js';

const origin = 'https://storage.test';
const password = 'correct horse battery staple';
const encode = bytes => Buffer.from(bytes).toString('base64url');
function fixture() {
    const state = { fault: null, context: null, secret: null, unlocked: false, creates: 0, gets: 0, outputs: [] };
    const id = crypto.getRandomValues(new Uint8Array(32));
    const prf = crypto.getRandomValues(new Uint8Array(32));
    async function response(options, creating) {
        if (state.fault === (creating ? 'cancel-create' : 'cancel-get')) throw new DOMException('Cancelled', 'NotAllowedError');
        if (state.fault === 'timeout') throw new DOMException('Timed out', 'TimeoutError');
        const data = {
            type: creating ? 'webauthn.create' : 'webauthn.get',
            challenge: encode(options.publicKey.challenge), origin, crossOrigin: false,
        };
        if (state.fault === 'origin') data.origin = 'https://other.test';
        if (state.fault === 'challenge') data.challenge = 'wrong';
        if (state.fault === 'cross-origin') data.crossOrigin = true;
        if (state.fault === 'type') data.type = 'webauthn.wrong';
        const auth = new Uint8Array(37);
        auth.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('storage.test'))));
        auth[32] = state.fault === 'no-uv' ? 1 : state.fault === 'no-up' ? 4 : 5;
        if (state.fault === 'rp-hash') auth[0] ^= 1;
        const credentialId = !creating && state.fault === 'credential' ? new Uint8Array(32) : id;
        const output = state.fault === 'short-prf' ? prf.slice(0, 16) : prf.slice();
        if (!creating && state.fault === 'unstable-prf' && state.gets > 1) output[0] ^= 1;
        if (!creating) state.outputs.push(output);
        return {
            id: encode(credentialId), rawId: credentialId.buffer, type: 'public-key',
            response: { clientDataJSON: new TextEncoder().encode(JSON.stringify(data)), authenticatorData: auth.buffer },
            getClientExtensionResults() {
                if (creating) return { prf: { enabled: state.fault !== 'unsupported' } };
                if (state.fault === 'missing-prf') return {};
                if (state.fault === 'invalid-prf') return { prf: { results: { first: 'not bytes' } } };
                return { prf: { results: { first: output } } };
            },
        };
    }
    const credentials = {
        async create(options) {
            state.creates++;
            assert.equal(options.publicKey.authenticatorSelection.userVerification, 'required');
            assert.equal(options.publicKey.authenticatorSelection.residentKey, 'required');
            return response(options, true);
        },
        async get(options) {
            state.gets++;
            assert.equal(options.publicKey.userVerification, 'required');
            assert.equal(options.publicKey.rpId, 'storage.test');
            assert.deepEqual(new Uint8Array(options.publicKey.allowCredentials[0].id), id);
            return response(options, false);
        },
    };
    const storage = {
        async passkeyContext() { return structuredClone(state.context); },
        async enrollPasskey(given, context, secret) {
            assert.equal(given, password); state.context = structuredClone(context); state.secret = secret;
        },
        async unlockPasskey(context, secret) {
            assert.deepEqual(context, state.context); assert.equal(secret, state.secret); state.unlocked = true;
        },
    };
    return { state, storage, credentials };
}

test('creation and verified PRF assertion precede persistence; later unlock reproduces secret', async () => {
    const f = fixture();
    await enrollPasskey(f.storage, password, f.credentials, origin);
    assert.equal(f.state.creates, 1); assert.equal(f.state.gets, 2);
    assert.match(f.state.secret, /^[a-f0-9]{64}$/);
    assert(!JSON.stringify(f.state.context).includes(f.state.secret));
    await unlockPasskey(f.storage, f.credentials, origin);
    assert.equal(f.state.unlocked, true);
    assert(f.state.outputs.every(output => output.every(byte => byte === 0)), 'PRF bytes cleared');
});

for (const fault of ['cancel-create', 'cancel-get', 'timeout', 'unstable-prf', 'unsupported', 'missing-prf', 'short-prf', 'invalid-prf', 'origin', 'challenge', 'cross-origin', 'type', 'no-uv', 'no-up', 'rp-hash', 'credential']) {
    test(`enrollment rejects ${fault} without persisting access`, async () => {
        const f = fixture(); f.state.fault = fault;
        await assert.rejects(enrollPasskey(f.storage, password, f.credentials, origin));
        assert.equal(f.state.context, null);
    });
}

test('unlock failures leave access locked and retryable', async () => {
    const f = fixture();
    await enrollPasskey(f.storage, password, f.credentials, origin);
    const saved = structuredClone(f.state.context);
    for (const fault of ['cancel-get', 'missing-prf', 'no-uv', 'rp-hash', 'credential', 'origin', 'challenge', 'cross-origin']) {
        f.state.fault = fault;
        await assert.rejects(unlockPasskey(f.storage, f.credentials, origin));
        assert.equal(f.state.unlocked, false); assert.deepEqual(f.state.context, saved);
    }
    f.state.fault = null;
    await assert.rejects(unlockPasskey(f.storage, f.credentials, 'https://other.test'));
    f.state.context.rpId = 'other.test';
    await assert.rejects(unlockPasskey(f.storage, f.credentials, origin));
    f.state.context = saved;
    await unlockPasskey(f.storage, f.credentials, origin);
    assert.equal(f.state.unlocked, true);
});

test('insecure origins and unavailable credentials fail before creating a passkey', async () => {
    const f = fixture();
    await assert.rejects(enrollPasskey(f.storage, password, f.credentials, 'http://storage.test'));
    await assert.rejects(enrollPasskey(f.storage, password, {}, origin));
    assert.equal(f.state.creates, 0);
});

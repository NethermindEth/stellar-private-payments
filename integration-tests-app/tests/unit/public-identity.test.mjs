import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { lookupPublicIdentity } from '../../../app/js/public-identity.js';
const require = createRequire(new URL('../../../app/package.json', import.meta.url));
const { Keypair, StrKey, xdr, nativeToScVal, scValToNative } = require('@stellar/stellar-sdk');
const address = Keypair.random().publicKey();
const registry = StrKey.encodeContract(Buffer.alloc(32, 1));
const options = { address, registry, rpcUrl: 'https://testnet.example' };
const entry = value => ({ val: { value: { val: value } } });
test('public identity reads the registry Registration key and decodes both keys', async () => {
    const result = await lookupPublicIdentity(options, { getLedgerEntries: async key => {
        assert.equal(key.value.durability.name, 'persistent');
        assert.deepEqual(scValToNative(key.value.key), ['Registration', address]);
        return { entries: [entry(nativeToScVal({ note_key: Buffer.alloc(32, 2), encryption_key: Buffer.alloc(32, 3) }))] };
    } });
    assert.deepEqual(result, { status: 'registered', notePublicKey: '0x'+'02'.repeat(32), encryptionPublicKey: '0x'+'03'.repeat(32) });
});
test('missing active entries are distinct from RPC failures and malformed keys', async () => {
    assert.deepEqual(await lookupPublicIdentity(options, { getLedgerEntries: async () => ({ entries: [] }) }), { status: 'not-found' });
    await assert.rejects(lookupPublicIdentity(options, { getLedgerEntries: async () => { throw Error('offline'); } }), /offline/);
    await assert.rejects(lookupPublicIdentity(options, { getLedgerEntries: async () => ({ entries: [entry(xdr.ScVal.scvVoid())] }) }));
});

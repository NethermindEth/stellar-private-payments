import assert from 'node:assert/strict';
import test from 'node:test';
import { explorerPreference, saveExplorerPreference } from '../../../app/js/public-settings.js';
import { loadPrivateSigners } from '../../../app/js/private-signers.js';

function records() {
    const values = new Map();
    return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
}
test('public explorer preference persists without database access and rejects credential-bearing URLs', () => {
    const storage = records();
    saveExplorerPreference('https://stellar.expert/explorer/testnet', storage);
    assert.equal(explorerPreference(storage), 'https://stellar.expert/explorer/testnet');
    for (const url of ['javascript:alert(1)', 'https://user:secret@example.org', 'https://example.org/?token=secret']) {
        assert.throws(() => saveExplorerPreference(url, storage));
    }
});
test('legacy signer associations are removed only after encrypted persistence succeeds', async () => {
    const legacy = records();
    legacy.setItem('poolstellar_signers:owner', JSON.stringify(['signer']));
    const encrypted = { getSetting: async () => null, setSetting: async () => { throw Error('write failed'); } };
    await assert.rejects(loadPrivateSigners(encrypted, 'owner', legacy));
    assert.ok(legacy.getItem('poolstellar_signers:owner'));
    encrypted.setSetting = async (key, value) => {
        assert.equal(key, 'poolstellar_signers:owner');
        assert.deepEqual(value, ['signer']);
    };
    assert.deepEqual(await loadPrivateSigners(encrypted, 'owner', legacy), ['signer']);
    assert.equal(legacy.getItem('poolstellar_signers:owner'), null);
});
test('encrypted signer lists take precedence over stale plaintext lists', async () => {
    const legacy = records();
    legacy.setItem('poolstellar_signers:owner', JSON.stringify(['old']));
    assert.deepEqual(await loadPrivateSigners({ getSetting: async () => ['current'] }, 'owner', legacy), ['current']);
    assert.equal(legacy.getItem('poolstellar_signers:owner'), null);
});

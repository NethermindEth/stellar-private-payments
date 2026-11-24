import assert from 'node:assert/strict';
import test from 'node:test';
import { explorerPreference, saveExplorerPreference } from '../../../app/js/public-settings.js';
import { loadPrivateSigners, savePrivateSigners } from '../../../app/js/private-signers.js';

function records() {
    const values = new Map();
    return { get length() { return values.size; }, key: index => [...values.keys()][index] ?? null,
        getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
}
test('public explorer preference persists without database access and rejects credential-bearing URLs', () => {
    const storage = records();
    saveExplorerPreference('https://stellar.expert/explorer/testnet', storage);
    assert.equal(explorerPreference(storage), 'https://stellar.expert/explorer/testnet');
    for (const url of ['javascript:alert(1)', 'https://user:secret@example.org', 'https://example.org/?token=secret']) {
        assert.throws(() => saveExplorerPreference(url, storage));
    }
    // A network without a default explorer saves no preference.
    saveExplorerPreference('', storage);
    assert.equal(explorerPreference(storage), null);
});
test('signer lists round-trip through encrypted storage and default to empty', async () => {
    const saved = new Map();
    const encrypted = {
        getSetting: async key => saved.get(key) ?? null,
        setSetting: async (key, value) => { saved.set(key, value); },
    };
    assert.deepEqual(await loadPrivateSigners(encrypted, 'owner'), []);
    await savePrivateSigners(encrypted, 'owner', ['signer']);
    assert.deepEqual(saved.get('poolstellar_signers:owner'), ['signer']);
    assert.deepEqual(await loadPrivateSigners(encrypted, 'owner'), ['signer']);
    assert.deepEqual(await loadPrivateSigners(encrypted, 'other'), []);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { explorerPreference, saveExplorerPreference } from '../../../app/js/public-settings.js';
import { loadPrivateSigners, migratePrivateSigners } from '../../../app/js/private-signers.js';

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

test('unlock migrates every legacy owner, normalizes lists, and keeps unrelated settings', async () => {
    const legacy = records();
    const saved = new Map([['poolstellar_signers:owner-b', ['current']]]);
    legacy.setItem('poolstellar_signers:owner-a', JSON.stringify(['signer-a', 'owner-a', 7, 'signer-a']));
    legacy.setItem('explorer', 'preserve');
    legacy.setItem('poolstellar_signers:owner-b', JSON.stringify(['stale']));
    legacy.setItem('poolstellar_signers:owner-c', JSON.stringify(['signer-c']));
    const encrypted = {
        getSetting: async key => saved.get(key) ?? null,
        setSetting: async (key, value) => {
            assert.notEqual(legacy.getItem(key), null, 'plaintext remains until the write completes');
            saved.set(key, value);
        },
    };
    await migratePrivateSigners(encrypted, legacy);
    assert.deepEqual(saved.get('poolstellar_signers:owner-a'), ['signer-a']);
    assert.deepEqual(saved.get('poolstellar_signers:owner-b'), ['current']);
    assert.deepEqual(saved.get('poolstellar_signers:owner-c'), ['signer-c']);
    assert.equal(legacy.length, 1);
    assert.equal(legacy.getItem('explorer'), 'preserve');
    await migratePrivateSigners({ getSetting: () => assert.fail('completed migration needs no database calls') }, legacy);
});

test('migration resumes after a write failure without losing any remaining owner lists', async () => {
    const legacy = records();
    const saved = new Map();
    for (const owner of ['a', 'b', 'c']) legacy.setItem(`poolstellar_signers:${owner}`, JSON.stringify([`signer-${owner}`]));
    let fail = true;
    const encrypted = {
        getSetting: async key => saved.get(key) ?? null,
        setSetting: async (key, value) => {
            if (fail && key.endsWith(':b')) throw new Error('write failed');
            saved.set(key, value);
        },
    };
    await assert.rejects(migratePrivateSigners(encrypted, legacy), /write failed/);
    assert.equal(legacy.getItem('poolstellar_signers:a'), null);
    for (const owner of ['b', 'c']) assert.equal(legacy.getItem(`poolstellar_signers:${owner}`), JSON.stringify([`signer-${owner}`]));
    fail = false;
    await migratePrivateSigners(encrypted, legacy);
    assert.equal(legacy.length, 0);
    assert.equal(saved.size, 3);
});

test('malformed legacy lists do not block unlock migration or loading a connecting owner', async () => {
    for (const raw of ['{broken', '{}', 'null', '"invalid"']) {
        const legacy = records();
        legacy.setItem('poolstellar_signers:owner', raw);
        legacy.setItem('poolstellar_signers:another-broken-owner', raw);
        legacy.setItem('poolstellar_signers:valid-owner', JSON.stringify(['signer']));
        const saved = new Map();
        const encrypted = {
            getSetting: async key => saved.get(key) ?? null,
            setSetting: async (key, value) => { saved.set(key, value); },
        };
        const warnings = [];
        await migratePrivateSigners(encrypted, legacy, message => warnings.push(message));
        assert.equal(warnings.length, 1, 'one warning per sweep, even with multiple malformed entries');
        assert.match(warnings[0], /can still use your wallet/);
        assert.ok(!warnings[0].includes(raw));
        assert.equal(legacy.getItem('poolstellar_signers:owner'), raw);
        assert.equal(legacy.getItem('poolstellar_signers:another-broken-owner'), raw);
        assert.equal(saved.has('poolstellar_signers:owner'), false);
        assert.deepEqual(saved.get('poolstellar_signers:valid-owner'), ['signer']);
        assert.equal(legacy.getItem('poolstellar_signers:valid-owner'), null);
        // Wallet.connect uses this same loader; an entry recreated after unlock
        // must likewise return an empty in-memory list without rejecting.
        assert.deepEqual(await loadPrivateSigners(encrypted, 'owner', legacy, message => warnings.push(message)), []);
        assert.equal(warnings.length, 2);
        assert.equal(saved.has('poolstellar_signers:owner'), false);
        assert.equal(legacy.getItem('poolstellar_signers:owner'), raw);
        // A corrected entry can still migrate on a later unlock.
        legacy.setItem('poolstellar_signers:owner', JSON.stringify(['recovered-signer']));
        assert.deepEqual(await loadPrivateSigners(encrypted, 'owner', legacy), ['recovered-signer']);
        assert.equal(legacy.getItem('poolstellar_signers:owner'), null);
    }
});

test('failed legacy reads remain explicit and never delete unreadable data', async () => {
    await assert.rejects(loadPrivateSigners({ getSetting: async () => null }, 'owner', {
        getItem: () => { throw new Error('read failed'); },
        removeItem: () => assert.fail('unreadable data must not be deleted'),
    }), /read failed/);
});

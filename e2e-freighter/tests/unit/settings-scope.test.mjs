// Coverage for the setting-scoping rule.
//
// app-storage.js is import-free apart from its own constants, so unlike
// navigation.js or the wizard it loads directly under `node --test` and the
// rule can be asserted behaviourally rather than by reading source.

import assert from 'node:assert/strict';
import test from 'node:test';
import {
    ACCOUNT_SCOPED_SETTINGS,
    SETTING_BOOTNODE_CONFIG,
    SETTING_EXPLORER,
    SETTING_TELEMETRY_CONFIG,
    settingKey,
} from '../../../app/js/app-storage.js';

const ADDR_A = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ADDR_B = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

test('the archive endpoint and logging posture are account-scoped', () => {
    // A bootnode operator observes which account
    // is syncing, and revealSensitive un-redacts that account's Tier-1 values.
    assert.ok(ACCOUNT_SCOPED_SETTINGS.has(SETTING_BOOTNODE_CONFIG));
    assert.ok(ACCOUNT_SCOPED_SETTINGS.has(SETTING_TELEMETRY_CONFIG));
});

test('the block explorer stays global', () => {
    // Public infrastructure, identical for every account, reveals nothing about
    // who is signed in. Scoping it would cost the user a re-entry per account
    // and buy nothing.
    assert.ok(!ACCOUNT_SCOPED_SETTINGS.has(SETTING_EXPLORER));
    assert.equal(settingKey(SETTING_EXPLORER, ADDR_A), SETTING_EXPLORER);
    assert.equal(
        settingKey(SETTING_EXPLORER, ADDR_A),
        settingKey(SETTING_EXPLORER, ADDR_B),
        'a global setting must resolve to one key regardless of the account',
    );
});

test('two accounts never share a scoped key', () => {
    // The defect, stated directly: account B must not read account A's value.
    for (const key of ACCOUNT_SCOPED_SETTINGS) {
        assert.notEqual(settingKey(key, ADDR_A), settingKey(key, ADDR_B), key);
        assert.ok(settingKey(key, ADDR_A).includes(ADDR_A));
    }
});

test('a scoped read without an account is refused, not silently unscoped', () => {
    // Falling back to the bare key is precisely how account B inherited
    // account A's archive endpoint, so an absent address must throw rather
    // than quietly resolve to the shared key.
    for (const key of ACCOUNT_SCOPED_SETTINGS) {
        for (const missing of [undefined, null, '']) {
            assert.throws(
                () => settingKey(key, missing),
                /account-scoped and requires an address/,
                `${key} with address=${JSON.stringify(missing)}`,
            );
        }
    }
});

test('the legacy unscoped key is never produced for a scoped setting', () => {
    // A value written before this change belonged to whichever account was
    // active then. Adopting it for a different account would reproduce the
    // defect during the one upgrade the user is least likely to inspect.
    for (const key of ACCOUNT_SCOPED_SETTINGS) {
        assert.notEqual(settingKey(key, ADDR_A), key);
    }
});

test('scoped keys are stable for the same account', () => {
    assert.equal(settingKey(SETTING_BOOTNODE_CONFIG, ADDR_A), settingKey(SETTING_BOOTNODE_CONFIG, ADDR_A));
});

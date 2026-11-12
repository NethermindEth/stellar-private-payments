import assert from 'node:assert/strict';
import test from 'node:test';
import { ACCESS_STATES, describeAccess } from '../../../app/js/access-state.js';

const base = { mode: 'encrypted', storeExists: false, walletState: 'disconnected', walletConnected: false, unlocked: false, view: 'dashboard' };
const describe = overrides => describeAccess({ ...base, ...overrides });

test('a first visit offers only Connect and explains the signature', () => {
    const access = describe({});
    assert.equal(access.state, 'welcome');
    assert.equal(access.action, 'connect');
    assert.equal(access.label, 'Connect Freighter');
    assert.equal(access.showLock, false);
    assert.equal(access.showViews, false);
    assert.equal(access.cardVisible, true);
    assert.match(access.card.note, /sign a message, not a transaction/);
});

test('a returning user connects and unlocks with one action', () => {
    const access = describe({ storeExists: true });
    assert.equal(access.state, 'returning');
    assert.equal(access.action, 'connect');
    assert.equal(access.label, 'Connect & unlock');
    assert.equal(access.showLock, false);
    assert.equal(access.showViews, false);
});

test('connecting disables the account button until the wallet settles', () => {
    for (const storeExists of [false, true]) {
        const access = describe({ storeExists, walletState: 'connecting', walletConnected: true });
        assert.equal(access.state, 'connecting');
        assert.equal(access.action, 'none');
        assert.equal(access.busy, true);
        assert.equal(access.showViews, false);
    }
});

test('a connected wallet with locked storage offers only Unlock', () => {
    const access = describe({ storeExists: true, walletState: 'locked', walletConnected: true });
    assert.equal(access.state, 'locked');
    assert.equal(access.action, 'unlock');
    assert.equal(access.label, 'Unlock');
    assert.equal(access.showLock, false);
    assert.equal(access.showViews, false);
    assert.equal(access.cardVisible, true);
});

test('an unlock in progress cannot be started twice', () => {
    const access = describe({ storeExists: true, walletState: 'locked', walletConnected: true, storageState: 'unlocking' });
    assert.equal(access.state, 'locked');
    assert.equal(access.action, 'none');
    assert.equal(access.busy, true);
    assert.equal(access.label, 'Unlocking…');
    // Connecting names the whole step, including its unlock.
    assert.equal(describe({ walletState: 'connecting', walletConnected: true, storageState: 'unlocking' }).label, 'Connecting…');
});

test('open storage shows the app and a lock control', () => {
    const access = describe({ storeExists: true, walletState: 'ready', walletConnected: true, unlocked: true });
    assert.equal(access.state, 'ready');
    assert.equal(access.action, 'none');
    assert.equal(access.showLock, true);
    assert.equal(access.showViews, true);
    assert.equal(access.card, null);
    assert.equal(access.cardVisible, false);
});

test('open storage without a wallet keeps the app visible and offers Connect', () => {
    const access = describe({ storeExists: true, unlocked: true });
    assert.equal(access.state, 'ready');
    assert.equal(access.action, 'connect');
    assert.equal(access.label, 'Connect Freighter');
    assert.equal(access.showLock, true);
    assert.equal(access.showViews, true);
});

test('reconnecting while storage is open keeps the app visible', () => {
    const access = describe({ storeExists: true, unlocked: true, walletState: 'connecting', walletConnected: true });
    assert.equal(access.state, 'ready');
    assert.equal(access.busy, true);
    assert.equal(access.action, 'none');
    assert.equal(access.showViews, true);
});

test('Disclosure verification stays usable for visitors without an account', () => {
    assert.equal(describe({ view: 'disclosure' }).cardVisible, false);
    assert.equal(describe({ view: 'disclosure', storeExists: true }).cardVisible, false);
    // Generating receipts needs unlocked data, so say why it is missing.
    assert.equal(describe({ view: 'disclosure', storeExists: true, walletState: 'locked', walletConnected: true }).cardVisible, true);
});

test('a lock caused by inactivity says why and where to change it', () => {
    const locked = { storeExists: true, walletState: 'locked', walletConnected: true };
    const idle = describe({ ...locked, idleLockMinutes: 5 });
    assert.equal(idle.state, 'locked');
    assert.equal(idle.action, 'unlock');
    assert.equal(idle.card.title, 'Locked after 5 minutes of inactivity');
    assert.match(idle.card.note, /change the timeout in Settings/);
    assert.equal(describe({ ...locked, idleLockMinutes: 1 }).card.title, 'Locked after 1 minute of inactivity');
    // A lock the user chose needs no reason.
    assert.equal(describe(locked).card.title, 'Your private account is locked');
    // Only the locked card explains the timeout.
    assert.equal(describe({ storeExists: true, idleLockMinutes: 5 }).card.title, 'Welcome back');
});

test('the card names the tab it stands in for', () => {
    const labels = { dashboard: 'Overview', 'move-funds': 'Move Funds', advanced: 'Advanced', disclosure: 'Disclosure' };
    for (const [view, label] of Object.entries(labels)) {
        assert.equal(describe({ view }).viewLabel, label);
    }
    assert.equal(describe({ view: 'unknown' }).viewLabel, null);
});

test('plaintext storage never locks and never claims encryption', () => {
    const plaintext = overrides => describe({ mode: 'plaintext', ...overrides });
    assert.equal(plaintext({ storeExists: true }).label, 'Connect Freighter');
    // Plaintext storage opens without a signature, so a connected wallet only waits for it.
    assert.equal(plaintext({ storeExists: true, walletState: 'locked', walletConnected: true }).state, 'connecting');
    assert.equal(plaintext({ storeExists: true, walletState: 'ready', walletConnected: true, unlocked: true }).showLock, false);
    for (const state of [plaintext({}), plaintext({ storeExists: true })]) {
        assert.match(state.card.note, /unencrypted/);
        assert.doesNotMatch(`${state.card.title} ${state.card.body} ${state.card.note}`, /\bencrypted\b|sign a message/);
    }
});

test('every pending state has complete copy in both modes', () => {
    const inputs = {
        welcome: {},
        returning: { storeExists: true },
        connecting: { walletState: 'connecting', walletConnected: true },
        locked: { storeExists: true, walletState: 'locked', walletConnected: true },
    };
    for (const mode of ['encrypted', 'plaintext']) {
        for (const [state, input] of Object.entries(inputs)) {
            const access = describe({ mode, ...input });
            if (mode === 'plaintext' && state === 'locked') continue;
            assert.equal(access.state, state);
            assert.ok(ACCESS_STATES.includes(access.state));
            assert.ok(access.card.title && access.card.body, `${mode}/${state} is missing copy`);
        }
    }
});

test('an unknown storage mode is rejected', () => {
    assert.throws(() => describe({ mode: 'other' }), /storage mode/);
});

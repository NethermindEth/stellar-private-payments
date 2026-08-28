// Behavioral coverage for app/js/connect-pipeline.js. Drives every await
// with a deferred promise, supersedes mid-window, and asserts nothing
// further runs or publishes.

import assert from 'node:assert/strict';
import test from 'node:test';

import { runConnectStages } from '../../../app/js/connect-pipeline.js';

const ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const LIVE_ADDRESS = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ';
const NETWORK = {
    network: 'TESTNET',
    networkPassphrase: 'Test SDF Network ; September 2015',
    sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
};
const KEYS = { notePublicKey: 'npub', encryptionPublicKey: 'epub' };

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

// Let queued microtasks run so the pipeline advances past a resolved await.
const flush = () => new Promise((resolve) => setImmediate(resolve));

function harness() {
    const calls = [];
    const states = [];
    let supersededFlag = false;
    const gates = {
        connectWallet: deferred(),
        getNetwork: deferred(),
        bootnodeCheck: deferred(),
        initializeRuntime: deferred(),
        runOnboardingWizard: deferred(),
        openAccount: deferred(),
        backgroundSync: deferred(),
        userPublicKeys: deferred(),
        loadRuntimeState: deferred(),
        createAppPool: deferred(),
    };
    const deps = {
        superseded: () => supersededFlag,
        setWalletState: (state) => states.push(state),
        connectWallet: () => {
            calls.push('connectWallet');
            return gates.connectWallet.promise;
        },
        getNetwork: () => {
            calls.push('getNetwork');
            return gates.getNetwork.promise;
        },
        publishWallet: (published) => calls.push(['publishWallet', published]),
        bootnodeCheck: (rpcUrl, address) => {
            calls.push(['bootnodeCheck', rpcUrl, address]);
            return gates.bootnodeCheck.promise;
        },
        initializeRuntime: (rpcUrl, opts) => {
            calls.push(['initializeRuntime', rpcUrl, opts]);
            return gates.initializeRuntime.promise;
        },
        startWatcher: () => calls.push('startWatcher'),
        runOnboardingWizard: (args) => {
            calls.push(['runOnboardingWizard', args]);
            return gates.runOnboardingWizard.promise;
        },
        liveAddress: () => LIVE_ADDRESS,
        openAccount: (args) => {
            calls.push(['openAccount', args]);
            return gates.openAccount.promise;
        },
        backgroundSync: () => {
            calls.push('backgroundSync');
            return gates.backgroundSync.promise;
        },
        userPublicKeys: () => {
            calls.push('userPublicKeys');
            return gates.userPublicKeys.promise;
        },
        publishKeys: (keys) => calls.push(['publishKeys', keys]),
        loadRuntimeState: () => {
            calls.push('loadRuntimeState');
            return gates.loadRuntimeState.promise;
        },
        publishReady: (detail) => calls.push(['publishReady', detail]),
        createAppPool: () => {
            calls.push('createAppPool');
            return gates.createAppPool.promise;
        },
    };
    return {
        calls,
        states,
        gates,
        deps,
        supersede: () => {
            supersededFlag = true;
        },
    };
}

// Resolve every gate in order, flushing between stages. Returns the pipeline
// result. Used by the happy-path test and as the tail of teardown tests.
async function resolveAll(h, run) {
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.gates.openAccount.resolve();
    await flush();
    h.gates.backgroundSync.resolve();
    await flush();
    h.gates.userPublicKeys.resolve(KEYS);
    await flush();
    h.gates.loadRuntimeState.resolve();
    await flush();
    h.gates.createAppPool.resolve();
    return run;
}

test('a clean run walks every stage in order and ends ready', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    const result = await resolveAll(h, run);

    assert.equal(result.connected, true);
    assert.equal(result.address, LIVE_ADDRESS);
    assert.deepEqual(h.states, ['connecting', 'binding', 'ready']);
    assert.deepEqual(
        h.calls,
        [
            'connectWallet',
            'getNetwork',
            ['publishWallet', { address: ADDRESS, ...NETWORK }],
            ['bootnodeCheck', NETWORK.sorobanRpcUrl, ADDRESS],
            ['initializeRuntime', NETWORK.sorobanRpcUrl, { address: ADDRESS }],
            'startWatcher',
            [
                'runOnboardingWizard',
                { address: ADDRESS, networkPassphrase: NETWORK.networkPassphrase, bootnodeRequired: false },
            ],
            ['initializeRuntime', NETWORK.sorobanRpcUrl, { address: LIVE_ADDRESS }],
            ['openAccount', { networkPassphrase: NETWORK.networkPassphrase, userAddress: LIVE_ADDRESS }],
            'backgroundSync',
            'userPublicKeys',
            ['publishKeys', KEYS],
            'loadRuntimeState',
            ['publishReady', { address: LIVE_ADDRESS }],
            'createAppPool',
        ],
    );
});

test('the session is opened for the live address, not the one connect started with', async () => {
    // The watcher may re-bind App.state.wallet.address while the wizard is
    // open; everything past the wizard must act as that account.
    const h = harness();
    const run = runConnectStages(h.deps);
    await resolveAll(h, run);
    const open = h.calls.find((call) => Array.isArray(call) && call[0] === 'openAccount');
    assert.equal(open[1].userAddress, LIVE_ADDRESS);
});

test('a rebind re-initializes the runtime for the account a session is opened for', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    await resolveAll(h, run);
    const initCalls = h.calls.filter((call) => Array.isArray(call) && call[0] === 'initializeRuntime');
    assert.deepEqual(
        initCalls.map((call) => call[2]),
        [{ address: ADDRESS }, { address: LIVE_ADDRESS }],
        'the runtime must be re-initialized for the address a session is about to open, not left pointed at the pre-wizard one',
    );
});

test('no account switch means no redundant runtime re-initialization', async () => {
    const h = harness();
    h.deps.liveAddress = () => ADDRESS; // no rebind: same account throughout
    const run = runConnectStages(h.deps);
    await resolveAll(h, run);
    const initCalls = h.calls.filter((call) => Array.isArray(call) && call[0] === 'initializeRuntime');
    assert.equal(initCalls.length, 1, 'initializeRuntime must run once when the account never changed');
});

// --- supersession at each await -------------------------------------------

test('teardown during connectWallet blocks network read and publication', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.supersede();
    h.gates.connectWallet.resolve(ADDRESS);
    const result = await run;

    assert.equal(result.connected, false);
    assert.deepEqual(h.calls, ['connectWallet'], 'nothing past the abandoned await may run');
    assert.deepEqual(h.states, ['connecting'], 'the state must not advance for a dead session');
});

test('teardown during getNetwork blocks wallet publication', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.supersede();
    h.gates.getNetwork.resolve(NETWORK);
    const result = await run;

    assert.equal(result.connected, false);
    assert.deepEqual(h.calls, ['connectWallet', 'getNetwork']);
});

test('teardown during bootnodeCheck blocks runtime initialization', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.supersede();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(
        !h.calls.some((call) => Array.isArray(call) && call[0] === 'initializeRuntime'),
        'a superseded connect must not initialize the runtime',
    );
});

test('teardown during initializeRuntime blocks the wizard and the watcher', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.supersede();
    h.gates.initializeRuntime.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(!h.calls.includes('startWatcher'), 'no watcher for a session that is already over');
    assert.ok(
        !h.calls.some((call) => Array.isArray(call) && call[0] === 'runOnboardingWizard'),
        'no wizard for a session that is already over',
    );
});

test('teardown during the wizard blocks the binding hand-off', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.supersede();
    h.gates.runOnboardingWizard.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.deepEqual(h.states, ['connecting'], "'binding' must never be set for a dead session");
    assert.ok(
        !h.calls.some((call) => Array.isArray(call) && call[0] === 'openAccount'),
        'no account session may be opened after teardown',
    );
});

test('teardown during openAccount blocks the sync and key reads', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.supersede();
    h.gates.openAccount.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(!h.calls.includes('backgroundSync'));
    assert.ok(!h.calls.includes('userPublicKeys'));
});

test('teardown during backgroundSync blocks key publication', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.gates.openAccount.resolve();
    await flush();
    h.supersede();
    h.gates.backgroundSync.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(!h.calls.includes('userPublicKeys'));
    assert.ok(!h.calls.some((call) => Array.isArray(call) && call[0] === 'publishKeys'));
});

test('teardown during userPublicKeys blocks key publication', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.gates.openAccount.resolve();
    await flush();
    h.gates.backgroundSync.resolve();
    await flush();
    h.supersede();
    h.gates.userPublicKeys.resolve(KEYS);
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(
        !h.calls.some((call) => Array.isArray(call) && call[0] === 'publishKeys'),
        'keys read for a torn-down session must not be published',
    );
});

test('teardown during loadRuntimeState blocks the ready publication', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.gates.openAccount.resolve();
    await flush();
    h.gates.backgroundSync.resolve();
    await flush();
    h.gates.userPublicKeys.resolve(KEYS);
    await flush();
    h.supersede();
    h.gates.loadRuntimeState.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.ok(
        !h.calls.some((call) => Array.isArray(call) && call[0] === 'publishReady'),
        'wallet:ready must not fire for a session that no longer exists',
    );
});

test('teardown during createAppPool blocks the ready state', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.resolve(ADDRESS);
    await flush();
    h.gates.getNetwork.resolve(NETWORK);
    await flush();
    h.gates.bootnodeCheck.resolve({ bootnodeRequired: false });
    await flush();
    h.gates.initializeRuntime.resolve();
    await flush();
    h.gates.runOnboardingWizard.resolve();
    await flush();
    h.gates.openAccount.resolve();
    await flush();
    h.gates.backgroundSync.resolve();
    await flush();
    h.gates.userPublicKeys.resolve(KEYS);
    await flush();
    h.gates.loadRuntimeState.resolve();
    await flush();
    h.supersede();
    h.gates.createAppPool.resolve();
    const result = await run;

    assert.equal(result.connected, false);
    assert.deepEqual(
        h.states,
        ['connecting', 'binding'],
        "'ready' must never be published after teardown: it advertises a session that no longer exists",
    );
});

test('a stage error propagates to the caller', async () => {
    const h = harness();
    const run = runConnectStages(h.deps);
    h.gates.connectWallet.reject(new Error('user declined'));
    await assert.rejects(run, /user declined/);
});

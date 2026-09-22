import assert from 'node:assert/strict';
import test from 'node:test';
import { createStorageStartup } from '../js/storage-startup.js';

function fixture(status = 'active') {
    const calls = [];
    const handle = {};
    const migration = {
        async status() { calls.push('status'); return status; },
        async close() { calls.push('close'); },
    };
    const api = {
        async open(options) { calls.push(['plaintext', options]); return handle; },
        async openEncrypted(options) { calls.push(['encrypted', options]); return handle; },
        async openMigration(options) { calls.push(['migration', options]); return migration; },
    };
    const startup = createStorageStartup(api, async () => calls.push('initialize'));
    return { startup, api, migration, calls, handle };
}

const provider = () => new Uint8Array(32);

test('concurrent callers share initialization and one default plaintext handle', async () => {
    const { startup, calls, handle } = fixture();
    const first = startup.open();
    assert.equal(startup.open(), first);
    assert.throws(() => startup.configure({ mode: 'encrypted', keyProvider: provider }), /already configured/);
    assert.equal(await first, handle);
    assert.equal(await startup.open(), handle);
    assert.deepEqual(calls, ['initialize', ['plaintext', { workerUrl: undefined }]]);
});

test('configuration snapshots options and never requests encrypted creation', async () => {
    const { startup, calls } = fixture();
    const options = { mode: 'encrypted', keyProvider: provider, workerUrl: '/worker.js' };
    startup.configure(options);
    options.mode = 'plaintext';
    options.keyProvider = () => { throw Error('mutated'); };
    await startup.open();
    assert.deepEqual(calls, ['initialize', ['encrypted', {
        keyProvider: provider, workerUrl: '/worker.js', createNew: false,
    }]]);
});

test('bad configuration and creation options are rejected before opening', () => {
    const { startup, calls } = fixture();
    for (const options of [null, {}, { mode: 'unknown' }, { mode: 'encrypted' },
        { mode: 'migrated', keyProvider: 'key' }, { mode: 'plaintext', keyProvider: provider },
        { mode: 'encrypted', keyProvider: provider, createNew: true },
        { mode: 'plaintext', workerUrl: '' }, { mode: 'plaintext', workerUrl: {} }]) {
        assert.throws(() => startup.configure(options), TypeError);
    }
    assert.deepEqual(calls, []);
});

test('failed encrypted open retries the same provider and never permits plaintext fallback', async () => {
    const { startup, api, calls, handle } = fixture();
    let available = false;
    const retryProvider = async () => {
        if (!available) throw Error('locked');
        return provider();
    };
    const realOpen = api.openEncrypted;
    api.openEncrypted = async options => {
        await options.keyProvider();
        return realOpen(options);
    };
    startup.configure({ mode: 'encrypted', keyProvider: retryProvider });
    const first = startup.open();
    const second = startup.open();
    assert.equal(first, second);
    await assert.rejects(first, /locked/);
    assert.throws(() => startup.configure({ mode: 'plaintext' }), /already configured/);
    available = true;
    assert.equal(await startup.open(), handle);
    assert.equal(calls.filter(call => Array.isArray(call) && call[0] === 'plaintext').length, 0);
});

test('initialization failure retains configuration and permits a new attempt', async () => {
    const { api, calls } = fixture();
    let attempts = 0;
    const startup = createStorageStartup(api, async () => {
        if (++attempts === 1) throw Error('WASM unavailable');
    });
    startup.configure({ mode: 'encrypted', keyProvider: provider });
    await assert.rejects(startup.open(), /WASM unavailable/);
    assert.deepEqual(calls, []);
    assert.throws(() => startup.configure({ mode: 'plaintext' }), /already configured/);
    await startup.open();
    assert.equal(attempts, 2);
    assert.equal(calls[0][0], 'encrypted');
});

for (const status of ['active', 'cleaning', 'complete']) {
    test(`${status} migration closes control before opening encrypted data`, async () => {
        const { startup, calls, handle } = fixture(status);
        startup.configure({ mode: 'migrated', keyProvider: provider });
        assert.equal(await startup.open(), handle);
        assert.deepEqual(calls.map(call => Array.isArray(call) ? call[0] : call),
            ['initialize', 'migration', 'status', 'close', 'encrypted']);
        assert.equal(calls[1][1].createNew, false);
    });
}

for (const status of ['copying', 'prepared', 'aborted', 'unknown']) {
    test(`${status} migration stops startup and releases the coordinator`, async () => {
        const { startup, calls } = fixture(status);
        startup.configure({ mode: 'migrated', keyProvider: provider });
        await assert.rejects(startup.open(), /requires explicit action/);
        assert.deepEqual(calls.map(call => Array.isArray(call) ? call[0] : call),
            ['initialize', 'migration', 'status', 'close']);
    });
}

for (const failure of ['open', 'status', 'close']) {
    test(`migration ${failure} failure never opens a data database`, async () => {
        const { startup, api, migration, calls } = fixture();
        const fail = async () => { throw Error('control failed'); };
        if (failure === 'open') api.openMigration = fail;
        else migration[failure] = fail;
        startup.configure({ mode: 'migrated', keyProvider: provider });
        await assert.rejects(startup.open(), /control failed/);
        assert(!calls.some(call => Array.isArray(call) && ['plaintext', 'encrypted'].includes(call[0])));
        if (failure === 'status') assert(calls.includes('close'));
    });
}

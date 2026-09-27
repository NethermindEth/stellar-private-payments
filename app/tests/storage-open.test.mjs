import test from 'node:test';
import assert from 'node:assert/strict';
import { openStorage } from '../js/storage-open.js';
import { beginStorageActivity, withStorageActivity, storageActivityPending, lastStorageActivity } from '../js/storage-activity.js';

test('timed-out opening completes without a second create/unlock', async () => {
    const states = ['locked', 'opening', 'unlocked'];
    let calls = 0;
    await openStorage({ status: async () => states.shift() }, async () => {
        calls++; throw Error('operation timed out');
    });
    assert.equal(calls, 1);
});
test('retry after a timed-out status discovers completion without reopening', async () => {
    let calls = 0;
    await openStorage({ status: async () => 'unlocked' }, async () => { calls++; });
    assert.equal(calls, 0);
});
test('wrong password and unavailable status retain original failure', async () => {
    for (const after of ['locked', 'unavailable']) {
        let calls = 0;
        const error = Error('wrong password');
        const storage = { status: async () => {
            if (calls && after === 'unavailable') throw Error('timed out');
            return 'locked';
        } };
        await assert.rejects(openStorage(storage, async () => { calls++; throw error; }), e => e === error);
    }
});
test('foreground guards cover nested work and release on errors', async () => {
    const release = beginStorageActivity();
    assert.equal(storageActivityPending(), true);
    await assert.rejects(withStorageActivity(async () => { throw Error('cancelled'); }));
    assert.equal(storageActivityPending(), true);
    release(); release();
    assert.equal(storageActivityPending(), false);
    assert(lastStorageActivity() > 0);
});

test('opening and unresponsive workers have a bounded wait', async () => {
    const { settledStorageStatus } = await import('../js/storage-open.js');
    for (const status of [async () => 'opening', () => new Promise(() => {})]) {
        await assert.rejects(settledStorageStatus({ status }, { timeoutMs: 20 }),
            error => error.code === 'storage-opening-timeout' && /Reload/.test(error.message));
    }
});
test('recovery unlock is accepted without reopening', async () => {
    await openStorage({ status: async () => 'password-recovery-required' }, async () => {
        assert.fail('must not reopen a recovered database');
    });
});

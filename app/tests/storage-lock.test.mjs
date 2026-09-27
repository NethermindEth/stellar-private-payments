import test from 'node:test';
import assert from 'node:assert/strict';
import { closeAndReload } from '../js/storage-lock.js';

test('locking reloads after close succeeds, rejects, or throws', async () => {
    for (const close of [async () => {}, async () => { throw Error('closed'); }, () => { throw Error('unavailable'); }]) {
        let reloads = 0;
        await closeAndReload({ close }, { reload: () => reloads++, timeoutMs: 100 });
        assert.equal(reloads, 1);
    }
});
test('a stuck close cannot prevent reload, and late completion cannot reload twice', async () => {
    let complete; let reloads = 0;
    const pending = new Promise(resolve => { complete = resolve; });
    await closeAndReload({ close: () => pending }, { reload: () => reloads++, timeoutMs: 10 });
    assert.equal(reloads, 1);
    complete();
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(reloads, 1);
});

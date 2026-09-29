import test from 'node:test';
import assert from 'node:assert/strict';
import { AppStorage } from '../js/app-storage.js';

test('ordinary settings need no unlock; history, keys and unknown settings require it', async () => {
    let unlocked = false; let prompts = 0; const calls = [];
    const app = new AppStorage({ call: async request => { calls.push(request); return { Setting: null }; } }, async () => {
        prompts++;
        if (!unlocked) throw Error('cancelled');
    });
    await app.getExplorerSetting(); await app.setBootnodeConfig('https://example.org');
    assert.equal(prompts, 0);
    for (const access of [() => app.getGvkAuthoritySetting(), () => app.privacyKeysExist('account'), () => app.listOperations('account', 'pool', 10), () => app.setSetting('future-secret', 'value')]) {
        const before = calls.length;
        await assert.rejects(access(), /cancelled/);
        assert.equal(calls.length, before, 'cancel must not send the private request');
    }
    unlocked = true;
    await app.listOperations('account', 'pool', 10);
    assert.equal(calls.at(-1).ListOperations.address, 'account');
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { refreshTokenDecimals, resolveAmountContext, requireSamePool, readDisplayDecimals } from '../../../app/js/token-metadata.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const pool = id => ({ poolContractId: id });

test('metadata updates ready pools independently and discards an obsolete runtime', async () => {
  const slow = deferred();
  const pools = [pool('fast'), pool('slow')];
  let current = true;
  const updates = [];
  const fastUpdated = deferred();
  const account = { async pool({ poolContract }) {
    return { tokenDecimals: () => poolContract === 'slow' ? slow.promise : Promise.resolve(0) };
  } };
  const work = refreshTokenDecimals(pools, account, () => current, () => {
    updates.push(pools[0].decimals);
    fastUpdated.resolve();
  });
  await fastUpdated.promise;
  assert.equal(pools[0].decimals, 0);
  assert.equal(pools[1].decimals, undefined);
  current = false;
  slow.resolve(8);
  await work;
  assert.equal(pools[1].decimals, undefined);
  assert.deepEqual(updates, [0]);
});

test('failed metadata is nonfatal for displays and does not invent precision', async t => {
  t.mock.method(console, 'warn', () => {});
  const pools = [pool('bad')];
  let updated = false;
  await refreshTokenDecimals(pools, { async pool() { throw new Error('offline'); } },
    () => true, () => { updated = true; });
  assert.equal(pools[0].decimals, undefined);
  assert.equal(updated, false);
  assert.equal(console.warn.mock.callCount(), 1);
});

for (const stage of ['opening', 'reading']) {
  test(`a pool change while ${stage} rejects the transaction context`, async () => {
    const wait = deferred();
    const original = pool('A');
    let selected = original;
    let updates = 0;
    const account = { pool: async ({ poolContract }) => {
      assert.equal(poolContract, 'A');
      if (stage === 'opening') await wait.promise;
      return { tokenDecimals: () => stage === 'reading' ? wait.promise : Promise.resolve(6) };
    } };
    const work = resolveAmountContext(original, account, () => selected, () => updates++);
    selected = pool('B');
    wait.resolve(6);
    await assert.rejects(work, /Pool changed/);
    assert.equal(original.decimals, undefined);
    assert.equal(updates, 0);
  });
}

test('transaction metadata failures propagate and successful reads notify displays', async () => {
  const selected = pool('A');
  let updates = 0;
  const account = { async pool() { return { async tokenDecimals() { return 8; } }; } };
  const context = await resolveAmountContext(selected, account, () => selected, () => updates++);
  assert.equal(context.decimals, 8);
  assert.equal(selected.decimals, 8);
  assert.equal(updates, 1);
  assert.throws(() => requireSamePool(selected, pool('B')), /Pool changed/);
  assert.throws(() => requireSamePool(selected, pool('A')), /Pool changed/);
  await assert.rejects(resolveAmountContext(selected, {
    async pool() { return { async tokenDecimals() { throw new Error('offline'); } }; },
  }, () => selected, () => updates++), /offline/);
  assert.equal(updates, 1);
});

test('audit/display precision failures fall back while zero decimals stay valid', async t => {
  t.mock.method(console, 'warn', () => {});
  assert.equal(await readDisplayDecimals({ async tokenDecimals() { throw new Error('offline'); } }), null);
  assert.equal(await readDisplayDecimals({ async tokenDecimals() { return 0; } }), 0);
});

test('unchanged transaction and background precision do not notify displays', async () => {
  const selected = { poolContractId: 'A', decimals: 0 };
  const account = { async pool() { return { async tokenDecimals() { return 0; } }; } };
  let updates = 0;
  await resolveAmountContext(selected, account, () => selected, () => updates++);
  await refreshTokenDecimals([selected], account, () => true, () => updates++);
  assert.equal(updates, 0);
});

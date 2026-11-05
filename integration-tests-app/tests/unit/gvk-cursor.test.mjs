import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { queueCursorOp, releaseCursor } from '../../../app/js/gvk-cursor.js';

test('a released cursor is freed once its pending nextTx settles', async () => {
  let inFlight = 0;
  let settle;
  const freed = [];
  const cursor = {
    nextTx: () => {
      inFlight += 1;
      return new Promise((resolve) => { settle = resolve; }).finally(() => { inFlight -= 1; });
    },
    free: () => freed.push(inFlight),
  };
  const pending = queueCursorOp(() => cursor.nextTx());
  await new Promise(setImmediate);
  releaseCursor(cursor);
  await new Promise(setImmediate);
  assert.deepEqual(freed, []);
  settle(null);
  await pending;
  await queueCursorOp(() => {});
  assert.deepEqual(freed, [0]);
});

test('the panel releases its cursor before dropping or replacing it, and never frees it directly', async () => {
  const src = await readFile(new URL('../../../app/js/admin-gvk.js', import.meta.url), 'utf8');
  assert.match(src, /\nfunction resetAuditState\(\) \{\n  if \(state\.audit\) releaseCursor\(state\.audit\);\n  state\.audit = null;\n/);
  assert.match(src, /\n +const audit = await authority\.audit\(poolContractId\);\n +if \(state\.audit\) releaseCursor\(state\.audit\);\n +state\.audit = audit;\n/);
  assert.equal(src.match(/state\.audit = /g).length, 2);
  assert.doesNotMatch(src, /audit\.free\(\)/);
});

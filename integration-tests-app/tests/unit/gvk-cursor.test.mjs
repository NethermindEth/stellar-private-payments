import assert from 'node:assert/strict';
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

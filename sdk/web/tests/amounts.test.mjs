import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import init, { parseTokenAmount, readTokenDecimals } from '../js/index.js';

await init({ module_or_path: await readFile(new URL('../dist/stellar_private_payments_web_bg.wasm', import.meta.url)) });

test('public WASM facade preserves precision and u128 boundaries', () => {
  assert.equal(parseTokenAmount('1.25', 6), 1_250_000n);
  assert.equal(parseTokenAmount('12', 0), 12n);
  assert.equal(parseTokenAmount('9007199254740993.0000001', 7), 90071992547409930000001n);
  assert.equal(parseTokenAmount('340282366920938463463374607431768211455', 0), (1n << 128n) - 1n);
  assert.throws(() => parseTokenAmount('340282366920938463463374607431768211456', 0));
  assert.throws(() => parseTokenAmount('0.0000001', 6));
  assert.throws(() => parseTokenAmount('.', 7));
  assert.throws(() => parseTokenAmount('-1', 7));
});

test('JS metadata and input are validated before wasm coercion', () => {
  for (const decimals of [-1, 0.5, NaN, Infinity, 2 ** 32, '7', undefined]) {
    assert.throws(() => parseTokenAmount('1', decimals), /u32/);
  }
  assert.throws(() => parseTokenAmount(1.25, 7), /string/);
});

test('wallet-free metadata reads use RPC and propagate simulation failures', async t => {
  const token = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
  let simulationError = null;
  t.mock.method(globalThis, 'fetch', async request => {
    assert.equal(request.url, 'https://rpc.test/');
    const payload = await request.json();
    assert.equal(payload.method, 'simulateTransaction');
    assert.equal(typeof payload.params.transaction, 'string');
    const response = new Response(JSON.stringify({
      jsonrpc: '2.0', id: payload.id,
      result: { latestLedger: 1, error: simulationError, results: [{ xdr: 'AAAAAwAAAAg=' }] },
    }), { headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: request.url });
    return response;
  });
  assert.equal(await readTokenDecimals('https://rpc.test', token), 8);
  simulationError = 'contract failure';
  await assert.rejects(readTokenDecimals('https://rpc.test', token), /contract failure/);
});

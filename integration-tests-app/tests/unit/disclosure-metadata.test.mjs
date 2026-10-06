import assert from 'node:assert/strict';
import test from 'node:test';
import { createDisclosureMetadata } from '../../../app/js/disclosure-metadata.js';
import { formatAmount } from '../../../app/js/ui/notes-view.js';

const config = { network: 'testnet', pools: [{ poolContractId: 'pool', tokenContractId: 'token', asset: { kind: 'contract', symbol: 'T' } }] };

test('disconnected verification refreshes raw amounts using its own RPC and deployment', async () => {
  const labels = [];
  const metadata = createDisclosureMetadata(async () => config, async (rpc, token) => {
    assert.equal(rpc, 'https://rpc.test');
    assert.equal(token, 'token');
    return 8;
  }, () => labels.push(formatAmount(100_000_000n, metadata.value.symbol, metadata.value.decimals)));
  await metadata.refresh('https://rpc.test', 'pool', 'testnet');
  assert.deepEqual(labels, ['100000000 base units', '1 T']);
});

test('disclosure metadata failures and foreign receipts retain base units', async t => {
  t.mock.method(console, 'warn', () => {});
  let reads = 0;
  const metadata = createDisclosureMetadata(async () => config, async () => { reads++; throw new Error('offline'); }, () => {});
  await metadata.refresh('rpc', 'pool', 'testnet');
  await metadata.refresh('rpc', 'unknown', 'testnet');
  await metadata.refresh('rpc', 'pool', 'mainnet');
  assert.equal(reads, 1);
  assert.equal(metadata.value.decimals, null);
});

test('late precision from an earlier endpoint cannot overwrite the current receipt display', async () => {
  let finishOld;
  const metadata = createDisclosureMetadata(async () => config, rpc => rpc === 'old'
    ? new Promise(resolve => { finishOld = resolve; }) : Promise.resolve(0), () => {});
  const old = metadata.refresh('old', 'pool', 'testnet');
  await Promise.resolve();
  await metadata.refresh('new', 'pool', 'testnet');
  finishOld(8);
  await old;
  assert.equal(metadata.value.decimals, 0);
});

test('malformed amounts never become a false zero', () => {
  assert.equal(formatAmount('bad amount', 'T', 8), 'bad amount base units');
});

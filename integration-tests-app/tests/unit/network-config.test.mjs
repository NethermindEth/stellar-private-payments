import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../../../app/js/network-config.js', import.meta.url), 'utf8');
const { validateNetwork } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const config = { network: 'custom', displayName: 'Private test chain', networkPassphrase: 'identity', rpcUrl: 'https://testnet.example' };
test('compares passphrase, independently of URL and network name', () => {
  assert.doesNotThrow(() => validateNetwork(config, 'identity'));
  assert.throws(() => validateNetwork(config, 'wrong'), /Switch Freighter to Private test chain/);
});
test('legacy configs cannot silently bypass validation', () => {
  assert.throws(() => validateNetwork({ network: 'testnet' }, 'identity'), /missing networkPassphrase/);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const defaults = await readFile(new URL('../../../sdk/native/src/network_defaults.json', import.meta.url), 'utf8');
const source = (await readFile(new URL('../../../app/js/network-config.js', import.meta.url), 'utf8'))
  .replace("import knownNetworks from '../../sdk/native/src/network_defaults.json';", `const knownNetworks = ${defaults};`);
const { validateNetwork, networkPresentation } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const config = { network: 'custom', networkPassphrase: 'identity', rpcUrl: 'https://testnet.example' };
test('compares passphrase, independently of URL and network name', () => {
  assert.doesNotThrow(() => validateNetwork(config, 'identity'));
  assert.throws(() => validateNetwork(config, 'wrong'), /Switch Freighter to custom/);
});
test('legacy configs cannot silently bypass validation', () => {
  assert.throws(() => validateNetwork({ network: 'testnet' }, 'identity'), /missing networkPassphrase/);
});
test('known network presentation follows passphrase, ignoring aliases and legacy fields', () => {
  for (const [networkPassphrase, displayName, explorerUrl] of [
    ['Public Global Stellar Network ; September 2015', 'Mainnet', 'https://stellar.expert/explorer/public'],
    ['Test SDF Network ; September 2015', 'Testnet', 'https://stellar.expert/explorer/testnet'],
    ['Test SDF Future Network ; October 2022', 'Futurenet', ''],
    ['Standalone Network ; February 2017', 'Local network', ''],
  ]) {
    assert.deepEqual(networkPresentation({ network: 'alias', networkPassphrase,
      displayName: 'Wrong', explorerUrl: 'https://wrong.example', isTestnet: false }),
    { displayName, explorerUrl });
  }
});
test('custom networks do not inherit a known-network explorer', () => {
  assert.deepEqual(networkPresentation({ ...config, network: 'testnet' }),
    { displayName: 'testnet', explorerUrl: '' });
  assert.deepEqual(networkPresentation({ networkPassphrase: '__proto__' }),
    { displayName: 'Custom network', explorerUrl: '' });
});

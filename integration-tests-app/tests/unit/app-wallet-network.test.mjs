import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const moduleUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const walletUrl = new URL('../../../app/js/wallet.js', import.meta.url);
const source = await readFile(walletUrl, 'utf8');

async function walletWith(reply, config = { network: 'custom', networkPassphrase: 'identity', rpcUrl: 'https://deployment.example/rpc' }) {
  // Deliberately expose only getNetwork for network queries: importing the
  // Freighter-specific getNetworkDetails must fail this regression test.
  const freighter = moduleUrl(`
    export async function getNetwork() { return ${JSON.stringify(reply)}; }
    export const WatchWalletChanges = class {};
    export const getAddress = () => {};
    export const isAllowed = () => {};
    export const isConnected = () => {};
    export const requestAccess = () => {};
    export const setAllowed = () => {};
    export const signAuthEntry = () => {};
    export const signTransaction = () => {};
    export const signMessage = () => {};
  `);
  return import(moduleUrl(source
    .replace("'@stellar/freighter-api'", JSON.stringify(freighter))
    .replace("'./wasm-facade.js'", JSON.stringify(moduleUrl(`export async function loadDeploymentConfig() { return ${JSON.stringify(config)}; }`)))
    .replace("'./network-config.js'", JSON.stringify(new URL('../../../app/js/network-config.js', import.meta.url).href))
    .replace("'./wallet-signer-guard.js'", JSON.stringify(new URL('../../../app/js/wallet-signer-guard.js', import.meta.url).href))));
}

test('SEP network identity uses deployment RPC without requiring wallet URLs', async () => {
  const wallet = await walletWith({ network: 'wallet alias', networkPassphrase: 'identity' });
  assert.deepEqual(await wallet.getWalletNetwork(), {
    network: 'wallet alias', networkPassphrase: 'identity', sorobanRpcUrl: 'https://deployment.example/rpc',
  });
});

test('wallet endpoint settings cannot override the deployment RPC', async () => {
  const wallet = await walletWith({ network: 'custom', networkPassphrase: 'identity', sorobanRpcUrl: 'https://wallet.example/rpc', networkUrl: 'https://wallet.example' });
  assert.equal((await wallet.getWalletNetwork()).sorobanRpcUrl, 'https://deployment.example/rpc');
});

test('a different wallet network is rejected before returning an endpoint', async () => {
  const wallet = await walletWith({ network: 'custom', networkPassphrase: 'wrong' });
  await assert.rejects(wallet.getWalletNetwork(), /Switch Freighter to custom/);
});

test('wallet network errors are surfaced', async () => {
  const wallet = await walletWith({ error: { message: 'Network unavailable', code: -1 } });
  await assert.rejects(wallet.getWalletNetwork(), { message: 'Network unavailable', code: 'WALLET_ERROR' });
});

test('missing deployment RPC is rejected even when the wallet supplies one', async () => {
  for (const rpcUrl of [undefined, null, '', '   ', 42]) {
    const wallet = await walletWith(
      { network: 'custom', networkPassphrase: 'identity', sorobanRpcUrl: 'https://wallet.example/rpc' },
      { network: 'custom', networkPassphrase: 'identity', rpcUrl },
    );
    await assert.rejects(wallet.getWalletNetwork(), /Deployment config is missing rpcUrl/);
  }
});

test('deployment RPC must be an absolute HTTP or HTTPS URL', async () => {
  for (const rpcUrl of ['/rpc', 'not-a-url', 'https://', 'file:///tmp/rpc', 'javascript:void(0)']) {
    const wallet = await walletWith(
      { network: 'custom', networkPassphrase: 'identity' },
      { network: 'custom', networkPassphrase: 'identity', rpcUrl },
    );
    await assert.rejects(wallet.getWalletNetwork(), /rpcUrl must be an absolute HTTP or HTTPS URL/);
  }
});

test('deployment RPC supports local HTTP endpoints', async () => {
  const rpcUrl = 'http://localhost:8000/rpc';
  const wallet = await walletWith(
    { network: 'custom', networkPassphrase: 'identity' },
    { network: 'custom', networkPassphrase: 'identity', rpcUrl },
  );
  assert.equal((await wallet.getWalletNetwork()).sorobanRpcUrl, rpcUrl);
});

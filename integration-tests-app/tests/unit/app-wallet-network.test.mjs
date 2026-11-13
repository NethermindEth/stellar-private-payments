import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';

const walletUrl = new URL('../../../app/js/wallet.js', import.meta.url);
let nextWalletId = 0;

async function walletWith(reply, config = { network: 'custom', networkPassphrase: 'identity', rpcUrl: 'https://deployment.example/rpc' }) {
  const id = ++nextWalletId;
  const isolatedWalletUrl = new URL(`?test=${id}`, walletUrl).href;
  const mockUrl = new URL(`./fixtures/app-wallet-network.mjs?test=${id}`, import.meta.url).href;
  const mocks = await import(mockUrl);
  mocks.configure(reply, config);

  // Resolve only this wallet instance's dependencies. Mock values stay data;
  // no test input is interpolated into JavaScript source.
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (context.parentURL === isolatedWalletUrl
          && (specifier === '@stellar/varial-sdk' || specifier === './wasm-facade.js')) {
        return { url: mockUrl, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });
  try {
    return await import(isolatedWalletUrl);
  } finally {
    hooks.deregister();
  }
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
  await assert.rejects(wallet.getWalletNetwork(), /Switch Varial to custom/);
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

test('mock responses preserve code-like strings as data', async () => {
  const network = '\'"` ${throw new Error("must remain data")} \\ </script>\n\u2028\u2029';
  const config = { network, networkPassphrase: network, rpcUrl: 'https://deployment.example/rpc' };
  const wallet = await walletWith({ network, networkPassphrase: network }, config);
  assert.deepEqual(await wallet.getWalletNetwork(), {
    network, networkPassphrase: network, sorobanRpcUrl: config.rpcUrl,
  });
});

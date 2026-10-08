import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Run the published JS entrypoint against a worker-boundary stub. No RPC or WASM needed.
const mockSource = `
export const configured = [];
export const clients = [];
export const ProverBridge = { spawn() { return {
  async configureCircuitsBase(base, json) { configured.push({base, lock: JSON.parse(json)}); },
  async ping() {}, toHandle() { return {free() {}}; }, fork() { return this; }, free() {}
}; }};
export const Storage = {async open() { return {
  async toHandle() { return {free() {}}; }, fork() { return this; }
}; }};
export const Client = {async new(rpc, storage, prover, config) {
  clients.push(config);
  return { contractConfig() { return config; }, free() {} };
}};
export function registerTelemetrySinks() { return {free() {}}; }
export async function verifySelectiveDisclosure(rpc, prover, receipt, hash, options) { return options.contractConfig; }
export class DisclosureRequest {};
export class WalletSigner {};
export function bootnodeRequired() {};
export function deriveAspUserLeaf() {};
export function configureTelemetry() {};
export function set_log_level() {};
export function dump_recent_logs() {};
export function debugLogsEnabled() {};
export default function init() {};
`;
const url = (source) => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const mockUrl = url(mockSource);
const sourceUrl = new URL('../../../sdk/web/js/index.js', import.meta.url);
const source = (await readFile(sourceUrl, 'utf8'))
  .replaceAll('../dist/stellar_private_payments_web.js', mockUrl)
  .replaceAll('import.meta.url', JSON.stringify(sourceUrl.href));
const sdk = await import(url(source));
const mock = await import(mockUrl);

test('one package passes each deployment and circuit lock to its own worker', async () => {
  for (const network of ['first', 'second']) {
    const contractConfig = { network, networkPassphrase: `identity ${network}` };
    const circuitLock = { version: network, meta: {}, circuit: { 'proving_key.bin': network } };
    const circuitsBaseUrl = `https://example.test/${network}/`;
    const client = await sdk.Client.new({rpcUrl: 'https://rpc.example', contractConfig, circuitLock, circuitsBaseUrl});
    assert.deepEqual(client.contractConfig(), contractConfig);
    assert.deepEqual(mock.configured.at(-1), {base: circuitsBaseUrl, lock: circuitLock});
    const report = await sdk.verifySelectiveDisclosure('rpc', '{}', 'hash', {contractConfig, circuitLock, circuitsBaseUrl});
    assert.deepEqual(report, contractConfig);
    assert.deepEqual(mock.configured.at(-1).lock, circuitLock);
    client.dispose();
  }
});

test('missing fingerprints fail before spawning a prover', async () => {
  const before = mock.configured.length;
  await assert.rejects(sdk.Client.new({contractConfig: {}, circuitsBaseUrl: 'https://example.test/'}), /circuitLock is required/);
  await assert.rejects(sdk.verifySelectiveDisclosure('rpc', '{}', 'hash', {contractConfig: {}, circuitsBaseUrl: 'https://example.test/'}), /circuitLock is required/);
  assert.equal(mock.configured.length, before);
});

test('app reopens clients and verifies receipts without fetching circuit fingerprints', async () => {
  const facadeUrl = new URL('../../../app/js/wasm-facade.js', import.meta.url);
  const lock = JSON.parse(await readFile(new URL('../../../deployments/testnet/circuits.json', import.meta.url), 'utf8'));
  const appSdkUrl = url(`
    export const opens = [];
    export const verifications = [];
    export const Client = { async new(options) {
      opens.push(options);
      return { stopBackgroundSync() {}, contractConfig() { return options.contractConfig; } };
    }};
    export const Storage = { async open() { return {}; } };
    export class DisclosureRequest {};
    export function bootnodeRequired() {};
    export function deriveAspUserLeaf() {};
    export async function verifySelectiveDisclosure(rpc, receipt, hash, options) { verifications.push(options); }
    export function configureTelemetry() {};
    export function dump_recent_logs() {};
    export function debugLogsEnabled() {};
    export default async function init() {};
  `);
  let facadeSource = await readFile(facadeUrl, 'utf8');
  facadeSource = facadeSource
    .replace("'stellar-private-payments'", JSON.stringify(appSdkUrl))
    .replace("'stellar-private-payments/freighter'", JSON.stringify(url('export class FreighterSigner {}')))
    .replace("'app-circuit-lock'", JSON.stringify(url(`export default ${JSON.stringify(lock)}`)));
  for (const name of ['network-config', 'app-storage']) {
    let moduleSource = await readFile(new URL(`../../../app/js/${name}.js`, import.meta.url), 'utf8');
    if (name === 'network-config') {
      const defaults = await readFile(new URL('../../../sdk/native/src/network_defaults.json', import.meta.url), 'utf8');
      moduleSource = moduleSource.replace("import knownNetworks from '../../sdk/native/src/network_defaults.json';", `const knownNetworks = ${defaults};`);
    }
    facadeSource = facadeSource.replace(`'./${name}.js'`, JSON.stringify(url(moduleSource)));
  }
  const previous = { fetch: globalThis.fetch, window: globalThis.window, document: globalThis.document };
  const requests = [];
  globalThis.window = { location: { href: 'https://app.example/' }, addEventListener() {} };
  globalThis.document = { baseURI: 'https://app.example/' };
  globalThis.fetch = async (input) => {
    requests.push(String(input));
    if (String(input) !== 'https://app.example/deployments.json') {
      throw new Error('artifact server unavailable');
    }
    return { ok: true, async json() { return { network: 'testnet' }; } };
  };
  try {
    const facade = await import(url(facadeSource));
    const appSdk = await import(appSdkUrl);
    await facade.initializeRuntime('https://rpc.example/', { bootnodeUrl: null });
    facade.disposeClient();
    await facade.initializeRuntime('https://rpc.example/', { bootnodeUrl: null });
    await facade.verifySelectiveDisclosure('https://rpc.example/', '{}', 'hash');
    assert.equal(appSdk.opens.length, 2);
    for (const options of [...appSdk.opens, ...appSdk.verifications]) {
      assert.deepEqual(options.circuitLock, lock);
    }
    assert.deepEqual(requests, ['https://app.example/deployments.json']);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete globalThis[key];
      else globalThis[key] = value;
    }
  }
});

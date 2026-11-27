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
export const Storage = {encryptedStorageEnabled() { return true; }, async open() { return {
  async toHandle() { return {free() {}}; }, fork() { return this; }
}; }};
export const Client = {async new(rpc, storage, prover, config) {
  clients.push(config);
  return { contractConfig() { return config; }, free() {} };
}};
export function registerTelemetrySinks() { return {free() {}}; }
export async function circuitsToPrepare() { return []; }
export class BlocklistOperator {};
export class PoolAdmin {};
export async function verifySelectiveDisclosure(rpc, prover, receipt, hash, options) { return options.contractConfig; }
export function readTokenDecimals() {};
export function parseTokenAmount() {};
export class DisclosureRequest {};
export class WalletSigner {};
export function bootnodeRequired() {};
export class AllowlistOperator {};
export function configureTelemetry() {};
export function set_log_level() {};
export function dump_recent_logs() {};
export function debugLogsEnabled() {};
export default function init() {};
`;
const url = (source) => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const mockUrl = url(mockSource);
const sourceUrl = new URL('../../../sdk/web/js/index.js', import.meta.url);
const noThreadsUrl = url('export const threadedProverWorkerUrl = null;');
const source = (await readFile(sourceUrl, 'utf8'))
  .replaceAll('../dist/stellar_private_payments_web.js', mockUrl)
  .replaceAll('../dist/prover-threads.js', noThreadsUrl)
  .replaceAll('import.meta.url', JSON.stringify(sourceUrl.href));
const sdk = await import(url(source));
const mock = await import(mockUrl);

test('one package passes each deployment and circuit lock to its own worker', async () => {
  for (const network of ['first', 'second']) {
    const contractConfig = { network, networkPassphrase: `identity ${network}` };
    const circuitLock = { version: network, meta: {}, circuit: { 'proving_key.bin': network } };
    const circuitsBaseUrl = `https://example.test/${network}/`;
    const keyProvider = async () => new Uint8Array(32);
    const client = await sdk.Client.new({rpcUrl: 'https://rpc.example', contractConfig, circuitLock, circuitsBaseUrl, keyProvider});
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
    export function readTokenDecimals() {};
    export function parseTokenAmount() {};
    export class DisclosureRequest {};
    export function bootnodeRequired() {};
    export class AllowlistOperator {};
    export class BlocklistOperator {};
    export class PoolAdmin {};
    export async function verifySelectiveDisclosure(rpc, receipt, hash, options) { verifications.push(options); }
    export function configureTelemetry() {};
    export function dump_recent_logs() {};
    export function debugLogsEnabled() {};
    export const PANIC_EVENT = 'panic';
    export default async function init() {};
  `);
  let facadeSource = await readFile(facadeUrl, 'utf8');
  facadeSource = facadeSource
    .replace("'stellar-private-payments'", JSON.stringify(appSdkUrl))
    .replace("'stellar-private-payments/varial'", JSON.stringify(url('export class VarialSigner {}')))
    .replace("'@stellar/stellar-sdk'", JSON.stringify(url('export const StrKey = { decodeEd25519PublicKey() { return new Uint8Array(32); } };')))
    .replace("'app-circuit-lock'", JSON.stringify(url(`export default ${JSON.stringify(lock)}`)))
    .replace("'./storage-lock.js'", JSON.stringify(url('export async function closeAndReload() {} export function reloadOnPanic() {}')))
    .replace("'./storage-timeout.js'", JSON.stringify(url('export function startAutoLock() { return () => {}; } export async function loadAutoLockSetting() {} export function clearAutoLockSetting() {} export function autoLockMinutes() { return 5; }')))
    .replace("'./storage-key.js'", JSON.stringify(url('export async function openWalletStorage({ storage }) { return storage.open(); }')))
    .replace("'./storage-account-dialog.js'", JSON.stringify(url('export async function confirmStorageAccount() {}')))
    .replace("'./storage-signature.js'", JSON.stringify(url('export async function verifyStorageSignature() {}')))
    .replace("'./storage-backup.js'", JSON.stringify(url('export const STORAGE_RECORD_KEY = "k"; export async function exportStorageBackup() {} export async function importStorageBackup() {} export function parseBackup() {} export async function resetStorage() {} export async function hasEncryptedStorage() { return false; } export async function acquireStorageLease() { return async () => {}; }')))
    .replace("'./wallet.js'", JSON.stringify(url('export async function getWalletAddress() {} export async function signWalletMessage() {} export function startWalletWatcher() {}')));
  for (const name of ['network-config', 'app-storage']) {
    let moduleSource = await readFile(new URL(`../../../app/js/${name}.js`, import.meta.url), 'utf8');
    if (name === 'network-config') {
      const defaults = await readFile(new URL('../../../sdk/native/src/network_defaults.json', import.meta.url), 'utf8');
      moduleSource = moduleSource.replace("import knownNetworks from '../../sdk/native/src/network_defaults.json' with { type: 'json' };", `const knownNetworks = ${defaults};`);
    }
    facadeSource = facadeSource.replace(`'./${name}.js'`, JSON.stringify(url(moduleSource)));
  }
  const previous = { fetch: globalThis.fetch, window: globalThis.window, document: globalThis.document, sessionStorage: globalThis.sessionStorage };
  const requests = [];
  globalThis.sessionStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
  globalThis.window = { location: { href: 'https://app.example/' }, addEventListener() {}, dispatchEvent() {} };
  globalThis.document = { baseURI: 'https://app.example/', body: { dataset: {}, style: {} } };
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

// Prover worker selection, against a bridge that records what it is asked.
async function loadSdk({ threadedUrl, threadsFail, poolThreads = 4 }) {
  const bridge = url(`
    export const spawned = [];
    export const threadRequests = [];
    export const freed = [];
    export const fallbacks = [];
    export const ProverBridge = { spawn(workerUrl) {
      spawned.push(workerUrl);
      return {
        async configureThreads(n) {
          threadRequests.push(n);
          if (${JSON.stringify(Boolean(threadsFail))}) throw new Error('worker did not start');
          return Math.min(n, ${JSON.stringify(poolThreads)});
        },
        fallBackToSerialOnTimeout(serialUrl) { fallbacks.push([workerUrl, serialUrl]); },
        fellBackToSerial() { return false; },
        async configureCircuitsBase() {}, async ping() {}, toHandle() { return { free() {} }; },
        fork() { return this; }, free() { freed.push(workerUrl); },
      };
    }};
  `);
  const mockForBridge = url(mockSource.replace('export const ProverBridge', 'const _unused').replace(
    'export default function init() {};',
    `export { ProverBridge } from ${JSON.stringify(bridge)}; export default function init() {};`,
  ));
  const marker = url(`export const threadedProverWorkerUrl = ${JSON.stringify(threadedUrl ?? null)};`);
  const text = (await readFile(sourceUrl, 'utf8'))
    .replaceAll('../dist/stellar_private_payments_web.js', mockForBridge)
    .replaceAll('../dist/prover-threads.js', marker)
    .replaceAll('import.meta.url', JSON.stringify(sourceUrl.href));
  return { sdk: await import(url(text)), bridge: await import(bridge) };
}

test('prover worker selection follows the build, isolation and proverThreads', async (t) => {
  const THREADED = 'https://example.test/workers/prover-worker-threads.js';
  const options = {
    rpcUrl: 'https://rpc.example', contractConfig: {}, circuitLock: {},
    circuitsBaseUrl: 'https://example.test/', keyProvider: async () => new Uint8Array(32),
  };
  const saved = { isolated: globalThis.crossOriginIsolated, warn: console.warn, navigator: Object.getOwnPropertyDescriptor(globalThis, 'navigator') };
  const warnings = [];
  console.warn = (...args) => warnings.push(args);
  const setCores = (hardwareConcurrency) =>
    Object.defineProperty(globalThis, 'navigator', { value: { hardwareConcurrency }, configurable: true, writable: true });
  setCores(16);
  t.after(() => {
    globalThis.crossOriginIsolated = saved.isolated;
    console.warn = saved.warn;
    if (saved.navigator) Object.defineProperty(globalThis, 'navigator', saved.navigator);
    else delete globalThis.navigator;
  });
  const run = async (load, isolated, extra = {}) => {
    globalThis.crossOriginIsolated = isolated;
    const client = await load.sdk.Client.new({ ...options, ...extra });
    const info = client.proverInfo();
    client.dispose();
    return { info, spawned: load.bridge.spawned.at(-1) };
  };
  const serialUrl = (spawned) => spawned.endsWith('/workers/prover-worker.js');

  // A default build never asks for the threaded worker.
  const plain = await loadSdk({});
  let r = await run(plain, true, { proverThreads: 8 });
  assert.deepEqual(r.info, { mode: 'serial', threads: 1 });
  assert.ok(serialUrl(r.spawned));
  assert.deepEqual(plain.bridge.threadRequests, []);

  const threaded = await loadSdk({ threadedUrl: THREADED });
  r = await run(threaded, true, { proverThreads: 8 });
  assert.deepEqual(r.info, { mode: 'threaded', threads: 4 });
  assert.equal(r.spawned, THREADED);
  assert.deepEqual(threaded.bridge.threadRequests, [8]);
  // A threaded worker falls back to the serial one on a timeout, and dispose frees it.
  assert.ok(threaded.bridge.fallbacks.at(-1)[0] === THREADED && serialUrl(threaded.bridge.fallbacks.at(-1)[1]));
  assert.equal(threaded.bridge.freed.at(-1), THREADED);

  // The request is clamped to the cores before choosing: one core never spawns the threaded worker.
  setCores(1);
  let count = threaded.bridge.spawned.length;
  r = await run(threaded, true, { proverThreads: 8 });
  assert.deepEqual(r.info, { mode: 'serial', threads: 1 });
  assert.equal(threaded.bridge.spawned.length, count + 1);
  assert.ok(serialUrl(r.spawned));
  setCores(16);

  // A pool that settles on one thread: the threaded worker is freed and the serial one used.
  const single = await loadSdk({ threadedUrl: THREADED, poolThreads: 1 });
  r = await run(single, true, { proverThreads: 8 });
  assert.deepEqual(r.info, { mode: 'serial', threads: 1 });
  assert.deepEqual(single.bridge.spawned.slice(-2).map((u, i) => i === 0 ? u : serialUrl(u)), [THREADED, true]);
  assert.equal(single.bridge.freed[0], THREADED);

  // Walletless verification uses the serial worker unless threads are asked for.
  count = threaded.bridge.threadRequests.length;
  await threaded.sdk.verifySelectiveDisclosure('rpc', '{}', 'hash', options);
  assert.ok(serialUrl(threaded.bridge.spawned.at(-1)));
  assert.equal(threaded.bridge.threadRequests.length, count);

  // Not isolated, switched off, or capped at one thread: serial, and the threaded worker is not spawned.
  const before = threaded.bridge.spawned.length;
  for (const [isolated, extra] of [[false, {}], [true, { proverThreads: false }], [true, { proverThreads: 1 }]]) {
    r = await run(threaded, isolated, extra);
    assert.deepEqual(r.info, { mode: 'serial', threads: 1 });
    assert.ok(serialUrl(r.spawned));
  }
  assert.equal(threaded.bridge.spawned.length, before + 3);
  assert.ok(!threaded.bridge.spawned.slice(before).includes(THREADED));

  // An explicit worker URL wins and is not asked about threads.
  const asked = threaded.bridge.threadRequests.length;
  r = await run(threaded, true, { proverWorkerUrl: 'https://example.test/mine.js' });
  assert.deepEqual(r.info, { mode: 'custom', threads: null });
  assert.equal(r.spawned, 'https://example.test/mine.js');
  assert.equal(threaded.bridge.threadRequests.length, asked);

  // A threaded worker that does not start is freed and the serial worker takes over, once.
  const broken = await loadSdk({ threadedUrl: THREADED, threadsFail: true });
  r = await run(broken, true, { proverThreads: 2 });
  assert.deepEqual(r.info, { mode: 'serial', threads: 1 });
  assert.deepEqual(broken.bridge.spawned.slice(-2).map((u, i) => i === 0 ? u : serialUrl(u)), [THREADED, true]);
  assert.equal(broken.bridge.freed[0], THREADED);
  assert.equal(warnings.length, 1);

  // An invalid proverThreads is rejected before storage is opened.
  let keyRequests = 0;
  const keyProvider = async () => { keyRequests += 1; return new Uint8Array(32); };
  for (const bad of [0, -1, 1.5, 2 ** 32, '4', null]) {
    await assert.rejects(run(threaded, true, { proverThreads: bad, keyProvider }), bad === '4' || bad === null ? TypeError : RangeError);
  }
  assert.equal(keyRequests, 0);
});

# Stellar Private Payments Browser SDK

Transact Stellar assets privately, from JavaScript/TypeScript. See the project
[README](../../README.md) for how the protocol works.

> **Work in progress**: not audited and not production-ready.

[![npm](https://img.shields.io/npm/v/stellar-private-payments.svg)](https://www.npmjs.com/package/stellar-private-payments)

```bash
npm install stellar-private-payments
```

## Quick start

```js
import init, { Storage, Client, bootnodeRequired } from 'stellar-private-payments';
import { FreighterSigner } from 'stellar-private-payments/freighter';

const networkPassphrase = 'Test SDF Network ; September 2015';
const rpcUrl = 'https://soroban-testnet.stellar.org';
const contractConfig = await fetch('/deployments.json').then((r) => r.json());
const circuitsBaseUrl = new URL('./circuits/', import.meta.url).href;
const signer = new FreighterSigner();

await init();

const storage = await Storage.open();

if (await bootnodeRequired(rpcUrl, storage, { contractConfig })) {
  // load or prompt for a bootnode URL, then pass it to Client.new
}

const client = await Client.new({ rpcUrl, storage, contractConfig, circuitsBaseUrl });
await client.backgroundSync();

const account = await client.account({ networkPassphrase }, signer);
await account.derivePrivacyKeys(); // idempotent; prompts the wallet only the first time

const pool = await account.pool({ poolContract: 'CA2TZ...' });
await pool.deposit(10_000_000n); // stroops (1 XLM)
const balance = await pool.balance(); // bigint stroops
await pool.transfer('G...', 5_000_000n);
await pool.withdraw(3_000_000n); // defaults to connected wallet
```

### Walletless verification

Verify a selective-disclosure receipt without a `Storage` / `Client` session:

```js
import { verifySelectiveDisclosure } from 'stellar-private-payments';

const report = await verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, {
  contractConfig,
  circuitsBaseUrl,
});
```

## API reference

Method names mirror the [Rust SDK](../native/README.md). Full signatures live in
the generated types: [`js/types/api-types.d.ts`](./js/types/api-types.d.ts)
(`Client`, `Account`, `PrivatePool`, options) and
[`js/types/index.d.ts`](./js/types/index.d.ts) (package entry).

## Signer

Bound at `client.account()`. Must implement `signMessage`, `signTransaction`,
and `signAuthEntry` (see [`js/types/signer.d.ts`](./js/types/signer.d.ts)).
Optional Freighter adapter: `stellar-private-payments/freighter` (requires
peer `@stellar/freighter-api`).

## Logging & Diagnostics

The SDK emits `tracing` spans and events in Rust, controllable from JS:

```js
import { configureTelemetry, dump_recent_logs, set_log_level } from 'stellar-private-payments';

configureTelemetry({
  level: 'debug',             // 'info' | 'debug' | 'trace'
  sink: 'both',               // 'console' | 'ringBuffer' | 'both'
  ringBufferBytes: 256 * 1024,
  revealSensitive: true,      // reveal Tier-1 values (debug profile only)
});

const logs = await dump_recent_logs(); // main thread + storage/prover workers
set_log_level('info');
```

## TypeScript

Public types live under [`js/types/`](./js/types/): `api-types.d.ts` (JS
facade), `index.d.ts` (package entry), and the gitignored, build-staged
`crates/stellar_private_payments_web.d.ts` (wasm-bindgen domain types). Low-level
wasm classes are available as `WasmClient`, `WasmAccount`, `WasmStorage`, or
via `stellar-private-payments/wasm`.

After building WASM:

```bash
npm run build
npm run check:bindgen   # wasm exports ⊆ public .d.ts; staged crates/ === dist/
npm run check:types
```

Both checks need a full build first — `crates/stellar_private_payments_web.d.ts`
only exists once `scripts/stage-wasm-types.sh` has staged it from `dist/`.

## Workers

Web Workers are used for the provided storage (SQlite OPFS) and prover implementations.
`Storage.open()` defaults to the bundled storage worker URL via
`import.meta.url`; override with `workerUrl` on `Storage.open()` or
`storageWorkerUrl` on `Client.new()`. The prover worker URL defaults the same
way (`proverWorkerUrl`), loading circuit artifacts from `dist/circuits/`.

## Build & publish (maintainers)

Building the npm package from source requires the monorepo, `wasm-bindgen-cli`, and [Binaryen](https://github.com/WebAssembly/binaryen) `wasm-opt` (see CONTRIBUTING.md):

```bash
make circuits
npm run build
npm pack
```

Published tarball: `dist/` (WASM, workers, **bundled circuits** + LGPL source bundle) and `js/` (entry + types).

CI publishes from `main` when `version` in `package.json` is bumped (see `.github/workflows/release.yml`).

### Binaryen / `wasm-opt`

The build script (`scripts/build.sh`) optimizes every shipped circuit witness
module with `wasm-opt -Os`. It pins Binaryen `version_131` and downloads the
matching release tarball for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`,
or `arm64-macos` when `wasm-opt` isn't already on `PATH` (needs `curl`, `tar`,
`sha256sum`/`shasum`).

To skip the download, install Binaryen 131 locally and set `WASM_OPT`:

```bash
export WASM_OPT=/usr/local/bin/wasm-opt
npm run build
```

The optimization cache lives under `target/tmp/witness-opt-cache/`, keyed by
the `wasm-opt` version, cargo profile, and enabled feature flags — safe to
delete at any time.

## Licensing (compiled circuits)

Compiled `.graph.bin` / `.r1cs` files incorporate [iden3/circomlib](https://github.com/iden3/circomlib) (LGPL-3.0). The npm package includes:

| Path | Purpose |
|------|---------|
| `dist/circuits/NOTICE.txt` | Circuit licensing notice |
| `dist/circuits/source-bundle.tar.gz` | Corresponding source to rebuild artifacts |
| `dist/licenses/LGPL-3.0.txt`, `GPL-3.0.txt` | License texts |
| `dist/LICENSE.txt` | Apache-2.0 (this SDK) |

The Pool Stellar web app uses the same legal layout via Trunk (`deployments/scripts/stage-dist-legal.sh`). If you redistribute the compiled circuits, comply with LGPL-3.0 (see NOTICE).

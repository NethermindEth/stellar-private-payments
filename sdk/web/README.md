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
// Bundle trusted fingerprints with your application using your bundler's JSON loader.
import circuitLock from './trusted-deployment/circuits.json';
// Fetching the lock beside the artifacts only detects corruption or mismatches;
// it cannot authenticate artifacts if that server can replace both.
const signer = new FreighterSigner();

await init();

// keyProvider must return the same recoverable 32-byte key on later opens.
const storage = await Storage.open({ keyProvider, createNew: false });

if (await bootnodeRequired(rpcUrl, storage, { contractConfig })) {
  // load or prompt for a bootnode URL, then pass it to Client.new
}

const client = await Client.new({ rpcUrl, storage, contractConfig, circuitsBaseUrl, circuitLock });
await client.backgroundSync();

const account = await client.account({ networkPassphrase }, signer);
await account.derivePrivacyKeys(); // idempotent; prompts the wallet only the first time

const pool = await account.pool({ poolContract: 'CA2TZ...' });
await pool.deposit(10_000_000n); // token base units (1 token if its decimals are 7)
const balance = await pool.balance(); // bigint token base units
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
  circuitLock,
});
```

The same package supports any compatible deployment. Supply its configuration,
artifact base URL, and expected fingerprints at runtime; no network-specific
package build is required. Each prover worker uses one bundle. To change bundles,
create a new client/prover instead of reconfiguring an active worker.

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
`crates/stellar_private_payments_web.d.ts` (wasm-bindgen domain types). The
package entry re-exports the low-level wasm types as `WasmClient`,
`WasmAccount`, and `WasmStorage` (types only); import the runtime classes from
`stellar-private-payments/wasm`.

After building WASM:

```bash
npm run build
npm run check:bindgen   # wasm exports ⊆ public .d.ts; staged crates/ === dist/
npm run check:types
```

Both checks need a full build first — `crates/stellar_private_payments_web.d.ts`
only exists once `scripts/stage-wasm-types.sh` has staged it from `dist/`.

## Workers

Web Workers run the OPFS SQLite storage backend and Groth16 prover off the main thread. `Storage.open()` and `Client.new()` resolve default worker URLs relative to `import.meta.url` (overridable via `workerUrl`, `storageWorkerUrl`, and `proverWorkerUrl`). When `Client.new()` opens storage itself instead of receiving a `storage` handle, pass `keyProvider` in its options.

## Build & publish (maintainers)

Browser builds compile SQLite3MC through `sqlite-wasm-rs` (`sqlite3mc` feature), which requires Clang and `llvm-ar` (or `ar`). Building the npm package from source also requires `wasm-bindgen-cli` and [Binaryen](https://github.com/WebAssembly/binaryen) `wasm-opt` (see [CONTRIBUTING.md](../../CONTRIBUTING.md)):

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

## Mandatory storage encryption

`Storage.open` and `Storage.openEncrypted` require a `keyProvider` before starting the storage worker; `createNew: true` initializes a new encrypted database, while `createNew: false` opens an existing one. All tables—including synced chain state and settings—live inside that encrypted SQLite database, with no plaintext fallback or automatic migration.

In the web app, `keyProvider` unwraps a random 32-byte key stored in `localStorage` using `HKDF-SHA-256` and `AES-256-GCM` from a verified Freighter signature in a dedicated storage domain (two matching signatures on enrollment, one on subsequent unlocks). Locking closes the storage worker and reloads the page to clear decrypted memory, either manually or after the configurable inactivity timeout.

### Encrypted backups and recovery

The app's **Local storage backup and recovery** controls export the encrypted OPFS files together with the wallet key envelope (up to 256 MiB). Exporting requires unlocked storage, closes the worker for a consistent snapshot, and reloads into the locked state. Because the backup contains only ciphertext and the wrapped key envelope, restoring it still requires the original unlocking wallet account.

Importing requires locked storage and a backup from the same origin (`scheme`, `host`, and `port`). The app stages the files in a new OPFS directory, prompts the enrolled wallet to unlock it, and verifies SQLite integrity and foreign keys before switching the active envelope and directory in a single `localStorage` write. Failed imports leave current storage unchanged, and restored backups replace local state as of export time without merging later changes.

If encrypted OPFS files exist without their `localStorage` key envelope, the wallet signature alone cannot recover the random database key; the app halts enrollment so the user can import a backup or reset storage. **Reset local storage** (confirmed by typing `DELETE` with other app tabs closed) deletes this origin's encrypted OPFS directories, key envelope, and legacy signer associations without affecting on-chain funds.

To run the isolated browser backup test after building the SDK:

```sh
node integration-tests-app/scripts/test-storage-backup.mjs
```

It uses ephemeral signing keys and a temporary Chromium profile (`E2E_CHROMIUM_PATH` overrides the browser binary) without a Stellar network.

### Token amounts

Transaction methods accept `bigint` base units. After SDK initialization, use
`parseTokenAmount` with the pool token's precision:

```js
import { parseTokenAmount } from 'stellar-private-payments';
const decimals = await pool.tokenDecimals();
await pool.deposit(parseTokenAmount('1.25', decimals));
```

The parser rejects invalid input, excess precision, negative nonzero values, and
`u128` overflow. It never rounds or converts through JavaScript `Number`.

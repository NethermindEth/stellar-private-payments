# stellar-private-payments (`sdk/web`)

Browser SDK for Stellar Private Payments.

> **Work in progress** — not audited and not production-ready.

**`Storage.open`** → **`bootnodeRequired`** → **`Client.new`** → **`backgroundSync`** → **`client.account()`** → **`account.pool()`** → **`PrivatePool`** (Rust SDK parity).

## Usage

```js
import init, {
  Storage,
  Client,
  bootnodeRequired,
  verifySelectiveDisclosure,
} from 'stellar-private-payments';
import { FreighterSigner } from 'stellar-private-payments/freighter';

const networkPassphrase = 'Test SDF Network ; September 2015';
const rpcUrl = 'https://soroban-testnet.stellar.org';
const contractConfig = await fetch('/deployments.json').then((r) => r.json());
const circuitsBaseUrl = new URL('./circuits/', import.meta.url).href;
const signer = new FreighterSigner();

await init();

const storage = await Storage.connect();
// Public chain syncing and ordinary settings work while private data is locked.

if (await bootnodeRequired(rpcUrl, storage, { contractConfig })) {
  // load or prompt for a bootnode URL, then pass it to Client.new
}

const client = await Client.new({
  rpcUrl,
  storage,
  contractConfig,
  circuitsBaseUrl,
  // bootnodeUrl: '...',
  // proverWorkerUrl defaults to package dist/workers/prover-worker.js
});

await client.backgroundSync();

// Ask for private access when the user opens their account, not at app startup.
const status = await storage.status();
// Obtain context and a verified, reproducible signature-derived secret.
// See app/js/storage-freighter.js for the full Freighter flow.
if (status === 'new' || status === 'unencrypted') await storage.createWallet(context, secret);
else if (status === 'locked') await storage.unlockWallet(context, secret);
else if (status !== 'unlocked') throw new Error(`Resolve storage status: ${status}`);

const account = await client.account({ networkPassphrase }, signer);
await account.derivePrivacyKeys(); // idempotent; prompts the wallet only the first time
console.log(await account.privacyKeys());
console.log(await account.isRegistered());

const pool = await account.pool({ poolContract: 'CA2TZ...' });
await client.sync(); // optional explicit catch-up
await pool.deposit(10_000_000n); // stroops (1 XLM)
console.log(await pool.balance()); // bigint stroops
await pool.transfer('G...', 5_000_000n);
await pool.withdraw(3_000_000n); // defaults to connected wallet

const cfg = client.contractConfig();
const feed = await client.operationalFeed(10);
const lookup = await client.recipientLookup('G...');
const chain = await client.allContractsData();

// Walletless verify (no Client / storage)
const report = await verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, {
  contractConfig,
  circuitsBaseUrl,
});
```

### `Storage`

| Method | Description                                              |
|--------|----------------------------------------------------------|
| `Storage.connect({ workerUrl? })` | Open the public chain cache once per page; the private vault stays closed |
| `status()` | `"new"`, `"unencrypted"` (earlier version's data), `"locked"` or `"unlocked"` |
| `createWallet(context, secret)` | Create the private vault or encrypt an earlier plaintext database with a wallet-derived secret |
| `unlockWallet(context, secret)` | Open the vault with its enrolled wallet secret |
| `walletContext()` | Read the public signing context before unlock |
| `reset()` | Explicitly delete local public and private data and the wallet record |
| `close()` | Release the database for this handle and its forks |
| `fork()` | Extra handle to the same worker (app + SDK share one DB) |
| `call(request, timeoutMs?)` | Raw worker RPC — **app-layer only** (disclaimer, explorer, bootnode, op history, `{ PrivacyKeys: address }` probe) |

The package exports a `Storage` namespace with `connect` only; the other methods are on the handle. The random vault key is unsealed using a signature-derived wallet secret inside the storage worker, so the page never holds the database key. `Client.new` accepts locked storage for public chain syncing and lookups. Private account data and operations require an unlocked vault.

### Free functions

| Function | Description |
|----------|-------------|
| `bootnodeRequired(rpcUrl, storage, { contractConfig })` | `true` if wallet RPC needs a historical-sync bootnode |
| `deriveAspUserLeaf(notePublicKey, membershipBlinding)` | ASP membership leaf from explicit hex inputs |
| `verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, { contractConfig, circuitsBaseUrl, proverWorkerUrl? })` | Walletless disclosure verification (no Storage / Client) |

### `Client`

| Method | Description |
|--------|-------------|
| `new({ rpcUrl, contractConfig, circuitsBaseUrl, storage?, proverWorkerUrl?, bootnodeUrl? })` | Build native client + spawn prover worker (no wallet yet) |
| `contractConfig()` | Deployment config for this client instance |
| `backgroundSync()` | Background contract-event sync |
| `stopBackgroundSync()` | Stop the background indexer (also on Client drop) |
| `sync()` | Explicit foreground catch-up |
| `operationalFeed(limit)` | Recent deployment activity |
| `recipientLookup(address)` | Recipient registry lookup |
| `account({ networkPassphrase, userAddress?, signerAddress? }, signer)` | Bind wallet and return `Account` |
| `aspState()` | On-chain ASP membership state |
| `allContractsData()` | On-chain pool + ASP state |
| `verifySelectiveDisclosure(receiptJson, expectedVkHash)` | Verify a disclosure receipt (uses this client's prover) |

### `verifySelectiveDisclosure` (standalone)

```ts
verifySelectiveDisclosure(rpcUrl, receiptJson, expectedVkHash, { contractConfig, circuitsBaseUrl, proverWorkerUrl? })
```

Walletless verification — no `Storage` / `Client`. Prover worker URL defaults to the package `dist/workers/` via `import.meta.url`.

### `Account`

| Method | Description |
|--------|-------------|
| `userAddress` | Connected Stellar address |
| `portfolio()` | Balances across all enabled pools |
| `privacyKeys()` | Note + encryption public keys |
| `derivePrivacyKeys()` | Derive and store privacy keys from the owner's wallet signature |
| `aspSecret()` | ASP membership blinding |
| `userNotes(limit)` | Notes across pools (newest first) |
| `isRegistered()` | On-chain public key registry entry exists |
| `deriveAspUserLeaf()` | ASP membership tree leaf from stored keys |
| `registerPublicKeys()` | On-chain key registry |
| `pool({ poolContract })` | Open a `PrivatePool` session |

### `PrivatePool`

Matches `stellar_private_payments::PrivatePool`. Amount parameters and `balance` use **stroops** as JavaScript `bigint`. There is **no** `pool.sync()` — use `backgroundSync` for background indexing and `client.sync()` when you need an explicit catch-up.

| Method | Description |
|--------|-------------|
| `balance()` | Spendable balance (stroops) |
| `notes()` | Notes for this pool |
| `estimate(amount)` | How many on-chain txs a spend needs |
| `deposit(amount)` | Deposit stroops |
| `transfer(recipient, amount)` | Private transfer to a `G...` address |
| `transferToKeys(notePkHex, encPkHex, amount)` | Private transfer to explicit note + encryption keys |
| `withdraw(amount, recipient?)` | Withdraw; `recipient` defaults to the connected wallet |
| `transact(config)` | Low-level pool transact |
| `disclose(config)` | Selective disclosure (`selectedCommitments` 1..=4); may return `null` if ASP registration is needed |
| `verifyDisclosure(receipt, expectedVkHash)` | Verify a disclosure receipt in this pool session |
| `audit(globalViewPrivateKeyHex)` | Open a {@link GvkAudit} cursor (pool-gvk deployments only) |

`GvkAudit.nextTx()` yields decrypted outputs, inputs (traceable pools), and nullifiers per on-chain `transact`, or `null` when exhausted.

`disclose` accepts `selectedCommitments` (1..=4 note commitment IDs); the prover picks the matching `selectiveDisclosure_N` circuit automatically.

### Signer

Bound at `client.account()`. Must implement `signMessage`, `signTransaction`, `signAuthEntry`.
Optional Freighter adapter: `import { FreighterSigner } from 'stellar-private-payments/freighter'` (requires peer `@stellar/freighter-api`).

When privacy keys are missing, `account.derivePrivacyKeys()` asks the note
owner to sign `Privacy Pool Key Derivation [v1]`. Custom `signMessage(message,
opts)` implementations must return a real SEP-53 Ed25519 signature: sign the
SHA-256 digest of the UTF-8 bytes of `"Stellar Signed Message:\n" + message`
with the owner's key. Return the 64 signature bytes as base64, either as a
string or as `{ signedMessage, signerAddress }`.

The SDK strictly verifies the signature against `userAddress` before deriving
or storing keys, even when the wallet reports no signer address. A signature
from another key, over another message, or with an invalid encoding or length
causes `derivePrivacyKeys()` to fail without saving privacy keys. Arbitrary
64-byte test stubs no longer work. If verification fails, check that the wallet
signed with the owner's account; this failure is not a wallet cancellation.

`signerAddress` defaults to the note owner and may name a different signing
account; `client.account()` opens the session without deriving or verifying
keys either way. Once keys are stored, `derivePrivacyKeys()` reuses them
without signing or verifying another derivation message. Existing stored keys
are not revalidated by this check.

## Logging & Diagnostics

The SDK provides integrated telemetry logging using `tracing` in Rust. You can configure and control logging from JavaScript:

```js
import { configureTelemetry, dump_recent_logs, set_log_level } from 'stellar-private-payments';

// Initialize or update telemetry settings
configureTelemetry({
  level: 'debug',             // 'info' | 'debug' | 'trace'
  sink: 'both',               // 'console' | 'ringBuffer' | 'both'
  ringBufferBytes: 256 * 1024, // 256 KiB buffer
  revealSensitive: true       // Reveal Tier-1 values (debug profile only)
});

// Dump recent logs (main thread + storage/prover workers) for diagnostic reports
const logs = await dump_recent_logs();

// Update log level filter on the fly
set_log_level('info');
```

## TypeScript

Public types live under [`js/types/`](./js/types/):

| Module | Role |
|--------|------|
| `crates/stellar_private_payments_web.d.ts` | wasm-bindgen domain types + session classes (staged from `dist/` on build; gitignored, never committed) |
| `api-types.d.ts` | JS facade (`Client.new`, `Account`, options, telemetry) |
| `index.d.ts` | Package entry — bindgen types + facade |

Low-level wasm classes are available as `WasmClient`, `WasmAccount`, and `WasmStorage`, or via `stellar-private-payments/wasm`.

```ts
import init, {
  Client,
  Storage,
  TX_PROGRESS_EVENT,
  type ContractConfig,
  type PoolExecuteResult,
} from 'stellar-private-payments';
```

After building WASM:

```bash
npm run build
npm run check:bindgen   # wasm exports ⊆ public .d.ts; staged crates/ === dist/
npm run check:types
```

`check:types` and `check:bindgen` both require a full build first: `js/types/crates/stellar_private_payments_web.d.ts` is gitignored and only exists once `scripts/stage-wasm-types.sh` has staged it from `dist/`.

## Build & publish (maintainers)

Every browser build includes the pinned SQLite3 Multiple Ciphers backend; `npm run build` and `make serve` configure it automatically through a Rust build tool. This requires Clang and an archive tool such as `llvm-ar` or `ar`. Creating an encrypted database remains an explicit runtime choice.

Building the npm package from source requires the monorepo, `wasm-bindgen-cli`, and [Binaryen](https://github.com/WebAssembly/binaryen) `wasm-opt` (see CONTRIBUTING.md):

```bash
make circuits
npm run build
npm pack
```

Published tarball: `dist/` (WASM, workers, **bundled circuits** + LGPL source bundle) and `js/` (entry + types).

### Binaryen / `wasm-opt`

The build script (`sdk/web/scripts/build.sh`) optimizes every shipped circuit witness module with `wasm-opt -Os`. It pins Binaryen **`version_131`** and downloads the matching release tarball for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, or `arm64-macos` when `wasm-opt` is not already on `PATH`. The download requires `curl`, `tar`, and `sha256sum` (or `shasum` on macOS).

- To skip the automatic download, install Binaryen 131 locally and point `WASM_OPT` at the binary:
  ```bash
  export WASM_OPT=/usr/local/bin/wasm-opt
  npm run build
  ```
- The optimization cache lives under `target/tmp/witness-opt-cache/` and is keyed by the actual `wasm-opt` version, the cargo profile, and the enabled feature flags. It is safe to delete at any time.

CI publishes from `main` when `version` in `package.json` is bumped (see `.github/workflows/release.yml`).

## npm install (app developers)

```bash
npm install stellar-private-payments
```

One package — no separate circuit hosting or Cargo build. Circuit artifacts ship under `dist/circuits/` and load automatically from the prover worker. Your bundler must serve static files from the package `dist/` tree (same as WASM and workers).

### Licensing (compiled circuits)

Compiled `.graph.bin` / `.r1cs` files incorporate [iden3/circomlib](https://github.com/iden3/circomlib) (LGPL-3.0). The npm package includes:

| Path | Purpose |
|------|---------|
| `dist/circuits/NOTICE.txt` | Circuit licensing notice |
| `dist/circuits/source-bundle.tar.gz` | Corresponding source to rebuild artifacts |
| `dist/licenses/LGPL-3.0.txt`, `GPL-3.0.txt` | License texts |
| `dist/LICENSE.txt` | Apache-2.0 (this SDK) |

The Pool Stellar web app uses the same legal layout via Trunk (`deployments/scripts/stage-dist-legal.sh`). If you redistribute the compiled circuits, comply with LGPL-3.0 (see NOTICE).

## Workers

`Storage.connect()` defaults to the bundled storage worker URL via `import.meta.url`. Override it with `workerUrl`. Prover worker URL defaults the same way on `Client.new()` (`proverWorkerUrl`). Circuit artifacts default to `dist/circuits/` via the prover worker loader.

### Wallet-only private storage

Freighter signs an origin-, account-, and random-salt-bound local-storage message
using SEP-0053. The app validates account, origin and signature and confirms two
matching signatures during initial setup. HKDF-SHA-256 derives a 32-byte wrapping
secret. The worker uses it directly with XSalsa20-Poly1305 to seal a random database
key in `wallet_record` in `spp.key.db`. Neither the signature nor wrapping secret
is persisted. Subsequent sessions need one wallet approval; privacy-key derivation
is a separate message when keys are missing.

`Storage.walletContext`, `Storage.createWallet`, and `Storage.unlockWallet`
are low-level APIs: the caller must derive the secret from a verified signature.
See `app/js/storage-freighter.js` for the application implementation.
There are no browser password, passkey, enrollment-removal or password-recovery
APIs. The native CLI retains password support.

Existing vaults with a Freighter record unlock with their original signing
context. After a successful open, the worker upgrades legacy envelopes and
removes old password/passkey records in one transaction. Data and the database
key are preserved. A vault without a Freighter record reports `recovery-required`
and refuses creation. Enroll Freighter using the previous version before upgrading,
or explicitly reset. Interrupted first setup reuses the saved wallet key.

### Storage API migration (0.3.0)

Use `Storage.connect` for public persistence and `createWallet` or `unlockWallet`
before private operations. This replaces browser password/passkey APIs from 0.2.0.
`Client.new` and public syncing work while locked. Status may be `opening`
(wait and re-query) or `recovery-required` (existing data cannot be opened through
the supported wallet route). A closed handle rejects further requests. An RPC
timeout does not cancel work in the worker; re-query status before retrying.
The app bounds this wait to two minutes.

Wallet compromise can expose a copied vault. Losing the wallet account loses
vault access. Migration does not rotate keys or revoke backups. See
[the at-rest security model](../../SECURITY.md).

Focused checks after building the SDK:

```sh
npm run test:storage --prefix e2e-freighter
cargo test --locked -p stellar-private-payments --lib wallet_vault
node sdk/web/scripts/test-sqlite3mc.js --artifacts /tmp/storage-check
```

The UI suite uses real Ed25519 signatures from a simulated signer. The storage
suite exercises real WASM/OPFS, process restarts and abrupt worker termination.
The real extension runner additionally covers first-run onboarding and reload.

### Public cache and private vault

`Storage.connect()` opens `spp.public.db` without asking for credentials. Public
chain ingestion, event processing, recipient lookups, operational feeds, and
explorer/bootnode settings are available immediately. Private requests reject
while locked, including key access, decrypted notes, balances, private history,
and all settings other than `explorer` and `bootnode_config`.

The existing `spp.encrypted.db` remains the encrypted private vault. It retains
chain rows referenced by its private notes, so each file has local foreign keys.
The first unlock seeds the public cache from explicitly selected public data;
subsequent unlocks replay public events into the vault using event IDs and
contract addresses rather than file-local IDs. Public progress commits together
with imported events. No private tables are copied into the cache. Wallet setup and legacy plaintext migration resume from the saved wallet envelope.

The app opens an unlock dialog on private access, with an option to continue
using public data. Manual/automatic locking closes workers and reloads to clear
private values from memory; reopening the public cache does not prompt. Public
sync can resume with a connected runtime. Reset deletes both files and the key
records. Public settings and followed contracts are readable at rest; see
[the security model](../../SECURITY.md).

Run `node tests/storage/public-private.mjs` from `e2e-freighter` after building the
SDK to verify public syncing, on-demand unlock, cancellation, private access
denial, and OPFS confidentiality in Chromium.

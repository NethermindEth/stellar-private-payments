# stellar-private-payments-sdk-web (`sdk/web`)

Browser SDK for Stellar Private Payments.

**`Storage.open`** → **`Client.new`** → **`checkSync`** → **`startSync`** → **`client.account()`** → **`account.pool()`** → **`PrivatePool`** (Rust SDK parity).

## Usage

```js
import init, { Storage, Client, FreighterSigner } from 'stellar-private-payments-sdk-web';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();

await init();

const storage = await Storage.open();
const client = await Client.new({
  storage,
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

const bootnodeUrl = await client.checkSync();
await client.startSync({ bootnodeUrl: bootnodeUrl ?? undefined });
const account = await client.account({ networkPassphrase }, signer);
await account.registerPublicKeys();

const pool = await account.pool({ poolContract: 'CA2TZ...' });
await pool.sync(); // optional foreground catch-up; prefer startSync for background indexing
await pool.deposit(10_000_000n); // stroops (1 XLM)
console.log(await pool.getBalance()); // bigint stroops
await pool.transfer('G...', 5_000_000n);
await pool.withdraw(3_000_000n);

const cfg = Client.contractConfig();
const chain = await account.allContractsData();
```

### `Storage`

| Method | Description                                              |
|--------|----------------------------------------------------------|
| `open({ workerUrl? })` | Spawn storage worker once per page (`spp.db` on OPFS)    |
| `fork()` | Extra handle to the same worker (app + SDK share one DB) |
| `call(request, timeoutMs?)` | Raw worker RPC for app-layer persistence                 |

### `Client`

| Method | Description |
|--------|-------------|
| `new({ storage, rpcUrl })` | Deployment client shell (no wallet yet) |
| `checkSync({ bootnodeUrl? })` | Probe RPC retention; returns bootnode URL or `null` |
| `startSync({ bootnodeUrl? })` | Background contract-event sync (once per page) |
| `contractConfig()` | Static deployment config |
| `account({ networkPassphrase, userAddress? }, signer)` | Bind wallet, spawn workers, return `Account` |
| `lookupRegisteredPublicKey(address)` | Recipient key lookup |
| `aspState()` | On-chain ASP membership state |
| `verifySelectiveDisclosure(receiptJson, expectedVkHash, options?)` | Walletless disclosure receipt verification |

### `Account`

| Method | Description |
|--------|-------------|
| `userAddress` | Connected Stellar address |
| `registerPublicKeys(options?)` | On-chain key registry (keys from storage by default) |
| `allContractsData()` | On-chain pool + ASP state |
| `pool({ poolContract })` | Open a `PrivatePool` session |

### `PrivatePool`

Matches `stellar_private_payments_sdk::PrivatePool`: `sync`, `getBalance`, `notes`, `estimate`, `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`. Mutating methods do **not** call `sync` automatically — use `startSync` for background indexing and call `pool.sync()` when you need an explicit catch-up (same as the Rust SDK). Amount parameters and `getBalance` use **stroops** as JavaScript `bigint`.

`disclose` accepts `selectedCommitments` (1..=4 note commitment IDs); the prover picks the matching `selectiveDisclosure_N` circuit automatically.

### Signer

Bound at `client.account()`. Must implement `signMessage`, `signTransaction`, `signAuthEntry`. See [`FreighterSigner`](./js/freighter.js).

## TypeScript

Public types live in [`js/types/`](./js/types/). The package entry (`import { Client } from 'stellar-private-payments-sdk-web'`) is fully typed; wasm-bindgen types are also available via `stellar-private-payments-sdk-web/wasm`.

```ts
import init, { Storage, Client, FreighterSigner, type WalletSigner } from 'stellar-private-payments-sdk-web';
```

After building WASM:

```bash
npm run build
npm run check:types
```

## Build & publish (maintainers)

Building the npm package from source requires the monorepo and `wasm-bindgen-cli` (see CONTRIBUTING.md):

```bash
cargo build -p circuits --release
npm run build
npm pack
```

Published tarball: `dist/` (WASM, workers, **bundled circuits** + LGPL source bundle) and `js/` (entry + types).

## npm install (app developers)

```bash
npm install stellar-private-payments-sdk-web
```

One package — no separate circuit hosting or Cargo build. Circuit artifacts ship under `dist/circuits/` and load automatically from the prover worker. Your bundler must serve static files from the package `dist/` tree (same as WASM and workers).

### Licensing (compiled circuits)

Compiled `.wasm` / `.r1cs` files incorporate [iden3/circomlib](https://github.com/iden3/circomlib) (LGPL-3.0). The npm package includes:

| Path | Purpose |
|------|---------|
| `dist/circuits/NOTICE.txt` | Circuit licensing notice |
| `dist/circuits/source-bundle.tar.gz` | Corresponding source to rebuild artifacts |
| `dist/licenses/LGPL-3.0.txt`, `GPL-3.0.txt` | License texts |
| `dist/LICENSE.txt` | Apache-2.0 (this SDK) |

The Pool Stellar web app uses the same legal layout via Trunk (`deployments/scripts/stage-dist-legal.sh`). If you redistribute the compiled circuits, comply with LGPL-3.0 (see NOTICE).

## Workers

`Storage.open()` defaults to the bundled storage worker URL via `import.meta.url`. Override with `workerUrl` on `Storage.open()` or `storageWorkerUrl` on `Client.new()` when storage is omitted. Prover worker URL defaults similarly on `client.account()`. Circuit artifacts default to `dist/circuits/` via the prover worker loader.

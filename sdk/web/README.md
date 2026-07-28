# stellar-private-payments-sdk-web (`sdk/web`)

Browser SDK for Stellar Private Payments.

**`Storage.open`** → **`bootnodeRequired`** → **`Client.new`** → **`backgroundSync`** → **`client.account()`** → **`account.pool()`** → **`PrivatePool`** (Rust SDK parity).

## Usage

```js
import init, {
  Storage,
  Client,
  FreighterSigner,
  bootnodeRequired,
} from 'stellar-private-payments-sdk-web';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();

await init();

const storage = await Storage.open();
const rpcUrl = 'https://soroban-testnet.stellar.org';

if (await bootnodeRequired(rpcUrl, storage)) {
  // load or prompt for a bootnode URL, then pass it to Client.new
}

const client = await Client.new({
  rpcUrl,
  storage,
  // bootnodeUrl: '...',
  // proverWorkerUrl defaults to package dist/workers/prover-worker.js
});

await client.backgroundSync();

const account = await client.account({ networkPassphrase }, signer);
console.log(await account.userPublicKeys());
console.log(await account.aspSecret()); // ASP membership blinding only
console.log(await account.isRegistered());

const pool = await account.pool({ poolContract: 'CA2TZ...' });
await client.sync(); // optional explicit catch-up
await pool.deposit(10_000_000n); // stroops (1 XLM)
console.log(await pool.balance()); // bigint stroops
await pool.transfer('G...', 5_000_000n);
await pool.withdraw(3_000_000n);

const cfg = Client.contractConfig();
const feed = await client.operationalFeed(10);
const lookup = await client.recipientLookup('G...');
const chain = await client.allContractsData();
```

### `Storage`

| Method | Description                                              |
|--------|----------------------------------------------------------|
| `open({ workerUrl? })` | Spawn storage worker once per page (`spp.db` on OPFS)    |
| `fork()` | Extra handle to the same worker (app + SDK share one DB) |
| `call(request, timeoutMs?)` | Raw worker RPC — **app-layer only** (disclaimer, explorer, bootnode, op history, `{ UserKeys: address }` probe) |

### Free functions

| Function | Description |
|----------|-------------|
| `bootnodeRequired(rpcUrl, storage)` | `true` if wallet RPC needs a historical-sync bootnode |

### `Client`

| Method | Description |
|--------|-------------|
| `new({ rpcUrl, storage?, proverWorkerUrl?, bootnodeUrl? })` | Build native client + spawn prover worker (no wallet yet) |
| `contractConfig()` | Static deployment config |
| `backgroundSync()` | Background contract-event sync |
| `stopBackgroundSync()` | Stop the background indexer (also on Client drop) |
| `sync()` | Explicit foreground catch-up |
| `operationalFeed(limit)` | Recent deployment activity |
| `recipientLookup(address)` | Recipient registry lookup |
| `account({ networkPassphrase, userAddress? }, signer)` | Bind wallet, spawn workers, derive keys if missing, return `Account` |
| `aspState()` | On-chain ASP membership state |
| `allContractsData()` | On-chain pool + ASP state |
| `verifySelectiveDisclosure(receiptJson, expectedVkHash)` | Walletless disclosure receipt verification |

### `Account`

| Method | Description |
|--------|-------------|
| `userAddress` | Connected Stellar address |
| `portfolio()` | Balances across all enabled pools |
| `userPublicKeys()` | Note + encryption public keys |
| `aspSecret()` | ASP membership blinding |
| `userNotes(limit)` | Notes across pools (newest first) |
| `isRegistered()` | On-chain public key registry entry exists |
| `deriveAspUserLeaf()` | ASP membership tree leaf from stored keys |
| `registerPublicKeys(options?)` | On-chain key registry |
| `pool({ poolContract })` | Open a `PrivatePool` session |

### Free functions

| Function | Description |
|----------|-------------|
| `deriveAspUserLeaf(notePublicKey, membershipBlinding)` | ASP membership leaf from explicit hex inputs |
| `bootnodeRequired(rpcUrl, storage)` | Whether historical-sync bootnode is needed |
| `verifySelectiveDisclosure(...)` | Walletless disclosure verification |

### `PrivatePool`

Matches `stellar_private_payments_sdk::PrivatePool`: `balance`, `notes`, `estimate`, `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`. There is **no** `pool.sync()` — use `backgroundSync` for background indexing and `client.sync()` when you need an explicit catch-up. Amount parameters and `balance` use **stroops** as JavaScript `bigint`.

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

`Storage.open()` defaults to the bundled storage worker URL via `import.meta.url`. Override with `workerUrl` on `Storage.open()` or `storageWorkerUrl` on `Client.new()` when storage is omitted. Prover worker URL defaults the same way on `Client.new()` (`proverWorkerUrl`). Circuit artifacts default to `dist/circuits/` via the prover worker loader.

# stellar-private-payments-sdk (`sdk/web`)

Browser SDK for Stellar Private Payments.

**`Storage.open`** → **`Client.new`** → **`checkEventSync`** → **`startEventSync`** → **`initialize`** → **`client.pool()`** → **`PrivatePool`** (Rust SDK parity).

## Usage

```js
import init, { Storage, Client, FreighterSigner } from 'stellar-private-payments-sdk';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();

await init();

const storage = await Storage.open();
const client = await Client.new({
  storage,
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

const bootnodeUrl = await client.checkEventSync();
await client.startEventSync({ bootnodeUrl: bootnodeUrl ?? undefined });
await client.initialize({ networkPassphrase }, signer);
await client.registerPublicKeys();

const pool = await client.pool({ poolContract: 'CA2TZ...' });
await pool.sync();
await pool.deposit('10');
console.log(await pool.getBalance());
await pool.transfer('G...', '5');
await pool.withdraw('3');

const cfg = Client.contractConfig();
const chain = await client.allContractsData();
```

### `Storage`

| Method | Description |
|--------|-------------|
| `open({ workerUrl? })` | Spawn storage worker once per page (`poolstellar.sqlite` on OPFS) |
| `fork()` | Extra handle to the same worker (app + SDK share one DB) |
| `call(request, timeoutMs?)` | Raw worker RPC for app-layer persistence |

### `Client`

| Method | Description |
|--------|-------------|
| `new({ storage, rpcUrl })` | Client shell (no wallet yet) |
| `checkEventSync({ bootnodeUrl? })` | Probe RPC retention; returns bootnode URL or `null` |
| `startEventSync({ bootnodeUrl? })` | Background contract-event sync (once per page) |
| `initialize({ networkPassphrase, userAddress? }, signer)` | Bind wallet, spawn workers, derive keys if missing |
| `contractConfig()` | Static deployment config |
| `registerPublicKeys(options?)` | On-chain key registry (keys from storage by default) |
| `lookupRegisteredPublicKey(address)` | Recipient key lookup |
| `allContractsData()` | On-chain pool + ASP state |
| `pool({ poolContract })` | Open a `PrivatePool` session |

### `PrivatePool`

Matches `stellar_private_payments_sdk::PrivatePool`: `sync`, `getBalance`, `notes`, `estimate`, `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`.

### Signer

Bound at `client.initialize`. Must implement `signMessage`, `signTransaction`, `signAuthEntry`. See [`FreighterSigner`](./js/freighter.js).

## TypeScript

Public types live in [`js/types/`](./js/types/). The package entry (`import { Client } from 'stellar-private-payments-sdk'`) is fully typed; wasm-bindgen types are also available via `stellar-private-payments-sdk/wasm`.

```ts
import init, { Storage, Client, FreighterSigner, type WalletSigner } from 'stellar-private-payments-sdk';
```

After building WASM:

```bash
npm run build
npm run check:types
```

## Build & publish

From repo root, `make install` installs `wasm-bindgen-cli` (see CONTRIBUTING.md).

```bash
cargo build -p circuits --release
npm run build
npm pack
```

Published tarball: `dist/` (wasm + workers) and `js/` (entry + types).

## Workers

`Storage.open()` defaults to the bundled storage worker URL via `import.meta.url`. Override with `workerUrl` on `Storage.open()` or `storageWorkerUrl` on `Client.new()` when storage is omitted. Prover worker URL defaults similarly on `client.initialize()`.

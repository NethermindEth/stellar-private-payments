# private-payments-sdk (`sdk/web`)

Browser SDK for Stellar Private Payments.

**`Client.connect`** → account ops → **`client.pool()`** → **`PrivatePool`** (Rust SDK parity).

## Usage

```js
import init, { Client, FreighterSigner } from 'private-payments-sdk';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();

await init();

const client = await Client.connect(
  { rpcUrl: 'https://soroban-testnet.stellar.org', networkPassphrase },
  signer,
);

await client.initialize();
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

### `Client`

| Method | Description |
|--------|-------------|
| `connect(options, signer)` | Workers + wallet session (one account) |
| `contractConfig()` | Static deployment config |
| `initialize()` | Derive and save privacy keys |
| `registerPublicKeys(options?)` | On-chain key registry (keys from storage by default) |
| `lookupRegisteredPublicKey(address)` | Recipient key lookup |
| `allContractsData()` | On-chain pool + ASP state |
| `pool({ poolContract })` | Open a `PrivatePool` session |

### `PrivatePool`

Matches `stellar_private_payments_sdk::PrivatePool`: `sync`, `getBalance`, `notes`, `estimate`, `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`.

### Signer

Bound at `Client.connect`. Must implement `signMessage`, `signTransaction`, `signAuthEntry`. See [`FreighterSigner`](./js/freighter.js).

## TypeScript

Public types live in [`js/types/`](./js/types/). The package entry (`import { Client } from 'private-payments-sdk'`) is fully typed; wasm-bindgen types are also available via `private-payments-sdk/wasm`.

```ts
import init, { Client, FreighterSigner, type WalletSigner } from 'private-payments-sdk';
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

Worker URLs default via `import.meta.url` in the JS entry. Override with `storageWorkerUrl` / `proverWorkerUrl` on `Client.connect()`.

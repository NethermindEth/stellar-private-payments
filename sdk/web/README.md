# private-payments-sdk (`sdk/web`)

Browser SDK for Stellar Private Payments. **`PrivatePool` is the main object**, exported directly from Rust via wasm-bindgen.

## Usage

```js
import init, { PrivatePool, FreighterSigner, installWalletBridge } from 'private-payments-sdk/js/index.js';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();
installWalletBridge(signer, networkPassphrase);

await init();
const pool = await PrivatePool.new({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase,
  poolContract: 'CA2TZ...',
  userAddress: await signer.getPublicKey(),
});

await pool.initialize();
await pool.sync();
await pool.deposit('10');
console.log(await pool.getBalance());
await pool.transfer('G...', '5');
await pool.withdraw('3');
```

## Build

```bash
cargo build -p circuits --release
bash sdk/web/scripts/build.sh
```

## Workers

- `dist/workers/storage-worker.js`
- `dist/workers/prover-worker.js`

Optional config keys: `storageWorkerUrl`, `proverWorkerUrl` on `PrivatePool.new()`.

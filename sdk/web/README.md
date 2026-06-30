# private-payments-sdk (`sdk/web`)

Browser SDK for Stellar Private Payments. **`PrivatePool`** matches the Rust `sdk/pool` high-level API. Account-level helpers are **free functions**.

## Usage

```js
import init, {
  PrivatePool,
  FreighterSigner,
  initialize,
  registerPublicKeys,
  contractConfig,
} from 'private-payments-sdk';

const networkPassphrase = 'Test SDF Network ; September 2015';
const signer = new FreighterSigner();
const rpcUrl = 'https://soroban-testnet.stellar.org';

await init();

// account-level (free functions)
await initialize(
  { rpcUrl, networkPassphrase, userAddress: await signer.getPublicKey() },
  signer,
);
await registerPublicKeys(
  {
    rpcUrl,
    networkPassphrase,
    userAddress: await signer.getPublicKey(),
    notePublicKeyHex: '0x...',
    encryptionPublicKeyHex: '0x...',
  },
  signer,
);

// pool session
const pool = await PrivatePool.new(
  { rpcUrl, networkPassphrase, poolContract: 'CA2TZ...' },
  signer,
);
await pool.sync();
await pool.deposit('10');
console.log(await pool.getBalance());
await pool.transfer('G...', '5');
await pool.withdraw('3');

const cfg = contractConfig();
const chain = await allContractsData(rpcUrl);
```

## Build

```bash
cargo build -p circuits --release
bash sdk/web/scripts/build.sh
```

## Workers

Worker URLs default via `import.meta.url` in the JS entry. Override with `storageWorkerUrl` / `proverWorkerUrl` in config objects.

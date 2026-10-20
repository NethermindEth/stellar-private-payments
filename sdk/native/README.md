# Stellar Private Payments Rust SDK

Transact Stellar assets privately. See the project [README](../../README.md) for
how the protocol works.

> **Work in progress**: not audited and not production-ready.

[![crates.io](https://img.shields.io/crates/v/stellar-private-payments.svg)](https://crates.io/crates/stellar-private-payments)
[![docs.rs](https://docs.rs/stellar-private-payments/badge.svg)](https://docs.rs/stellar-private-payments)

Add to your project:

```bash
cargo add stellar-private-payments
```

## Building

All SDK and CLI builds require the pinned SQLite3 Multiple Ciphers backend.
From the repository root, use:

```sh
cargo build -p stellar-private-payments-cli --release
cargo test -p stellar-private-payments --lib
cargo build -p stellar-private-payments-cli --release --target x86_64-unknown-linux-musl
```

Cargo needs a C compiler and `ar` (plus `musl-gcc` for musl). Native builds
compile the pinned SQLite3MC 2.5.1 amalgamation from the `sqlite3mc-src` crate;
WASM builds compile the same pinned backend via `sqlite-wasm-rs` (`sqlite3mc`
feature) using Clang and an LLVM-compatible archiver. Plain
`cargo build --target wasm32-unknown-unknown` requires no generated SQLite
configuration.

Including the backend does not encrypt a database automatically. Plaintext and
explicit encrypted creation remain separate API choices.

## Quick start

```rust
use stellar_private_payments::{
    CircuitStore, Client, LocalProver, LocalSigner, LocalStorage,
    types::{ContractConfig, NoteOwnerAddress, SignerAddress},
};

let deployment: ContractConfig = /* load from deployments/ */;
// Obtain this database's key from your caller-owned key provider.
let storage = LocalStorage::open_encrypted(
    "wallet.sqlite",
    key,
    stellar_private_payments::state::database_key::OpenPurpose::OpenExisting,
)?;

let lock = stellar_private_payments::circuit_lock(&std::fs::read_to_string("./circuits.json")?)?;
let store = CircuitStore::open("./circuits", lock);
store.ensure_blocking()?;
let artifacts = store.transact_artifacts()?;
let prover = LocalProver::from_artifacts(&artifacts)?;

let client = Client::init(
    "https://soroban-testnet.stellar.org",
    storage.into(),
    prover.into(),
    deployment,
    None, // optional bootnode URL
)?;

let signer = LocalSigner::new(
    "S...",
    "Test SDF Network ; September 2015",
    SignerAddress::new("G..."),
)?;

let account = client.account(NoteOwnerAddress::new("G..."), signer.into())?;
account.derive_privacy_keys().await?; // once per wallet; idempotent after that
let pool = account.pool("C...")?;

pool.deposit(10_000_000u128.into()).await?;
let balance = pool.balance().await?;
```

### Read-only client (no prover)

For balance, portfolio, notes, and sync without transact proving:

```rust
let client = Client::init_readonly(rpc_url, storage.into(), deployment, None)?;
```

## Blocking API

A synchronous (non-async) client is also provided under `stellar_private_payments::blocking`:

```rust
use stellar_private_payments::blocking::{Client, Account};
use stellar_private_payments::types::NoteOwnerAddress;

let client = Client::init(rpc_url, storage, prover.into(), deployment, None)?;
let account = client.account(NoteOwnerAddress::new("G..."), signer.into())?;
let portfolio = account.portfolio()?;
```

Method names mirror the async API; each call runs on an internal Tokio runtime.

## Custom implementations

`LocalStorage`, `LocalProver`, and `LocalSigner` are the built-in
implementations for storage (SQLite), proving, and signing. Bring your own for
any of the three by implementing the corresponding trait.

## Examples

See more ways to use the SDK in the [examples/](examples/) directory.

## Circuit artifacts

Transacting in the private pool means producing ZK proofs, which requires the
circuit artifacts the proofs are built against. Supply the deployment's trusted
`circuits.json` to `circuit_lock(&json)` and pass the result to
`CircuitStore::open(directory, lock)`. The same SDK supports different bundles
without rebuilding. `artifacts()` reads and checks local files; `ensure()` can
download the release specified by that lock when files are missing.

## Bootnode

Producing transact proofs requires the pool's full event history, but Stellar's
RPC only serves the last 7 days of events. Any pool older than that needs a
second source for the missing range.

For the deployment at `deployments/testnet/deployments.json` we run a bootnode
that serves those older events. For your own pool deployments, consider running
a [bootnode](../../tools/bootnode) as well.

## Beyond payments

- **Selective disclosure**: prove to a named authority that you own specific
  notes, without revealing the rest of your activity. See `disclosure::`.
- **Global View Key audit**: where a pool is deployed with GVK enabled, the
  key holder can reconstruct that pool's flows from synced state. See `gvk::`.

## Logging & Diagnostics

The SDK emits `tracing` spans and events. Install a subscriber such as
`tracing-subscriber` in your binary or tests, and include
`types::CorrelationIdLayer` so nested SDK calls inherit an ambient
`correlation_id`:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use stellar_private_payments::types::CorrelationIdLayer;

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(CorrelationIdLayer)
        .try_init();
}
```

See the CLI's `logging` module for a full example (human vs. JSON output) configuring the `TelemetryConfig` sink.

## Browser / WASM SDK

See [`../web/README.md`](../web/README.md). JS method names align with Rust where possible (`operationalFeed`, `recipientLookup`, `privacyKeys`, `isRegistered`).

## Mandatory storage encryption

All persistent SDK storage requires a 32-byte database key. Use
`LocalStorage::open_encrypted`, `LocalStorage::open_with_key_provider`, or
`SqliteStorage::connect_encrypted`. Keyless `open`, `connect`, `connect_file`,
and `connect_existing_plaintext` calls return an error without opening or
creating a file. In-memory storage remains available for transient computation.

The CLI unlocks storage with a Stellar CLI identity: pass `--storage-account <alias>`
or set `SPP_STORAGE_ACCOUNT` (also available as `defaults.storage_account` in the
TOML config). It defaults to `--account`, independently of `--sign-as`. Commands
without an account, such as `spp config show`, need an explicit storage identity.
The signing key remains managed by `stellar keys`, including its secure store.

On first use, two matching signatures of a dedicated storage message confirm that
unlocking is reproducible. HKDF-SHA-256 derives a wrapping key from the signature;
XSalsa20-Poly1305 seals a random database key. Later commands require one signature,
with the key cached for the command. These messages do not authorize transactions
and are separate from privacy-key derivation. The public signing context and sealed
key live in `spp.db.key`; back it up together with `spp.db`. Existing plaintext
databases are encrypted before use. Wrong identities or signatures preserve files.

### CLI storage threat model

Storage encryption protects a copied database and its `.key` file when the attacker
cannot use the enrolled signing identity. There is no independent storage password:
anyone who obtains that identity's private key, or can make it sign the storage
unlock message, can unwrap the database key and read the copied database.

If a Stellar CLI identity is stored as a plaintext secret in a configuration file,
an attacker who can read that file together with `spp.db` and `spp.db.key` can decrypt
the data. Encrypting the database does not provide a separate security boundary
against that level of filesystem access. An OS secure store or supported hardware
signer can protect the signing key, subject to its own access and approval controls.
Encryption also does not protect decrypted data from a compromised running process.

Each CLI invocation that opens storage invokes the Stellar CLI to sign the unlock
message. Depending on the identity's setup, this can require a secure-store or
hardware-wallet approval on each invocation. The unlocked key is cached only for
that command. This dependence on the wallet's security and availability is the
intentional tradeoff of wallet-based storage unlocking.

### Existing storage

The CLI encrypts existing plaintext databases before use. Encrypted databases need
their matching wallet key record; restore `spp.db` and `spp.db.key` together from
backup. Invalid key records are rejected without replacing existing files.

Browser storage uses a wallet-wrapped random database key through Freighter.
See the [browser backup and recovery instructions](../web/README.md#encrypted-backups-and-recovery).
The E2E setup uses the first provisioned Stellar identity to unlock its isolated database.

SDK callers supply a key or key provider; keyless callers fail closed.

### Token amounts

Transaction methods accept integer base units. Convert human input with the
pool token's precision:

```rust
let decimals = pool.token_decimals().await?;
let amount = NoteAmount::from_decimal("1.25", decimals)?;
pool.deposit(amount).await?;
```

`from_decimal` rejects excess precision and overflow without rounding.
`FromStr` continues to parse base units. `ExtAmount::from_decimal` supports signed
public amounts.

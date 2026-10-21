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

Native builds compile the SQLite3MC 2.5.1 amalgamation from `sqlite3mc-src` using a C compiler and `ar` (plus `musl-gcc` for `musl` targets). WASM builds compile the same SQLite3MC release through `sqlite-wasm-rs` (`sqlite3mc` feature) using Clang and an LLVM-compatible archiver.

```sh
cargo build -p stellar-private-payments-cli --release
cargo test -p stellar-private-payments --lib
cargo build -p stellar-private-payments-cli --release --target x86_64-unknown-linux-musl
```

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

Every persistent SQLite database is encrypted with SQLite3MC under a 32-byte `DatabaseKey`. Callers open storage through `LocalStorage::open_encrypted`, `LocalStorage::open_with_key`, or `SqliteStorage::connect_encrypted`, while `state::native_wallet::unlock_with_stellar` and `unlock_with` manage wallet-sealed key envelopes and migrate legacy plaintext files in place. In-memory storage (`SqliteStorage::connect_in_memory`) remains available for transient work.

On the command line, the CLI unlocks `spp.db` with a Stellar CLI identity (`--storage-account <alias>`, `SPP_STORAGE_ACCOUNT`, or `defaults.storage_account` in TOML). That identity defaults to `--account` rather than `--sign-as`, so changing the transaction payer does not switch which key unlocks local storage. Commands that take no `--account`, such as `spp config show`, require `--storage-account` (or its env/config equivalent) explicitly.

When initializing a database, the CLI asks the storage identity to sign a dedicated unlock message twice and checks that both signatures match before trusting the signer to be deterministic. It then derives a wrapping key from that signature with HKDF-SHA-256 and seals a random 32-byte database key with XSalsa20-Poly1305 in `spp.db.key`. Later runs request a single signature and reuse the unlocked key for the rest of the command. If `spp.db` is still an older plaintext database, the first open encrypts it in place. Because `spp.db.key` holds the wrapped random key, `spp.db` and `spp.db.key` must be backed up and restored together; a mismatched identity, invalid signature, or damaged key record aborts before modifying either file.

For browser storage and backups, see [`../web/README.md`](../web/README.md#encrypted-backups-and-recovery).

### CLI storage threat model

Encrypting `spp.db` under `spp.db.key` helps against a copied data directory only if an attacker cannot also sign the storage-unlock message with the enrolled identity. There is no separate storage password. If the Stellar CLI keeps that identity's secret key as an unencrypted file on the same disk, anyone who can read `spp.db` and `spp.db.key` can usually read the signing key too and unwrap the database. An OS secure store or hardware wallet is what puts a real boundary between the database files and the key that unlocks them, with the trade-off that each CLI invocation opening storage may prompt for signer approval. Once a command unlocks the database, plaintext state lives in process memory for the duration of that run.

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

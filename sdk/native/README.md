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

## Quick start

```rust
use stellar_private_payments::{
    CircuitStore, Client, LocalProver, LocalSigner, LocalStorage,
    types::{ContractConfig, NoteOwnerAddress, SignerAddress},
};

let deployment: ContractConfig = /* load from deployments/ */;
let storage = LocalStorage::open("wallet.sqlite")?;

let store = CircuitStore::open("./circuits");
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
let client = Client::init_readonly(rpc_url, storage, deployment, None)?;
```

## Blocking API

A synchronous (non-async) client is also provided under `stellar_private_payments::blocking`:

```rust
use stellar_private_payments::blocking::{Client, Account};
use stellar_private_payments::types::NoteOwnerAddress;

let client = Client::init(rpc_url, storage, prover, deployment, None)?;
let account = client.account(NoteOwnerAddress::new("G..."), signer)?;
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
circuit artifacts the proofs are built against. The SDK ships an embedded
circuit lockfile and downloads the matching GitHub release with
[`CircuitStore`].

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
[`types::CorrelationIdLayer`] so nested SDK calls inherit an ambient
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

See [`../web/README.md`](../web/README.md).

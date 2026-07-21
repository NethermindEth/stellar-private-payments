# Stellar Private Payments — Rust SDK (`stellar-private-payments-sdk`)

Native Rust client for privacy pool deposits, transfers, withdrawals, and local wallet state.

## Architecture

```
Client (deployment: sync, operational_feed, recipient_lookup)
  └─ account(signer) → Account (portfolio, user_notes, user_public_keys, is_registered, register_public_keys, sync, pool)
       └─ pool(id) → PrivatePool (deposit / transfer / withdraw / balance / notes)
```

- **Sync**: `Client::sync()` / `Account::sync()` catch local SQLite state up to chain tip via Soroban RPC. Pass an optional bootnode URL to `Client::init` for retention gaps.
- **`SyncMode::Inline`**: reads auto-sync before returning data (CLI default). Starts here after `init`.
- **`SyncMode::Background`**: after `Client::background_sync()`, `ensure_synced` kicks the background loop instead of awaiting catch-up (web default).

## Quick start

```rust
use stellar_private_payments_sdk::{
    Client, Handle, LocalProver, LocalSigner, LocalStorage, Prover, ProverArtifacts,
    types::{ContractConfig, PolicyFlags},
};

let deployment: ContractConfig = /* load from deployments/ */;
let storage = LocalStorage::open("wallet.sqlite")?;

// Load circuit bytes from your host environment, then wire a prover:
let artifacts: Vec<(PolicyFlags, ProverArtifacts)> = /* read from disk or embed */;
let prover = Handle::from_box(
    Box::new(LocalProver::from_artifacts(&artifacts)?) as Box<dyn Prover>,
);

let client = Client::init(
    "https://soroban-testnet.stellar.org",
    storage,
    prover,
    deployment,
    None, // optional bootnode URL
)?;

let signer = Handle::from_box(
    Box::new(LocalSigner::new("S...", "Test SDF Network ; September 2015", "G...")?)
        as Box<dyn stellar_private_payments_sdk::Signer>,
);

let account = client.account("G...", signer)?;
let pool = account.pool("C...")?;

pool.deposit(10_000_000u128.into()).await?;
let balance = pool.balance().await?;
```

### Read-only client (no prover)

For balance, portfolio, notes, and sync without transact proving:

```rust
let client = Client::init_readonly(rpc_url, storage, deployment, None)?;
```

The SDK does not read circuit files from disk — callers supply [`ProverArtifacts`] (or a custom [`Prover`] implementation). The CLI loads artifacts from its data directory; browser apps use worker-backed provers.

## Blocking API

For CLI and synchronous hosts, use `stellar_private_payments_sdk::blocking`:

```rust
use stellar_private_payments_sdk::blocking::{Client, Account};

let client = Client::init(rpc_url, storage, prover, deployment, None)?;
let account = client.account("G...", signer)?;
let portfolio = account.portfolio()?;
```

Method names mirror the async API; each call runs on an internal Tokio runtime.

## Key types

| Type | Role |
|------|------|
| `Client` | Deployment runtime, sync, chain reads |
| `Account` | Wallet session bound to one Stellar address |
| `PrivatePool` | Pool-scoped transact operations |
| `LocalStorage` | SQLite-backed `Storage` implementation |
| `PortfolioBalance` | Per-pool balance + note count |
| `RecipientLookup` | Registry lookup for private transfers |

### Privacy keys

| API | Role |
|-----|------|
| `KEY_DERIVATION_MESSAGE` | Wallet message to sign for key derivation (**native / CLI** — browser apps use `Client.account()`, which signs this internally) |
| `Account::user_public_keys()` | Note + encryption public keys for the bound account |
| `Account::asp_secret()` | ASP membership blinding for the bound account |
| `Account::derive_asp_user_leaf(...)` | ASP membership tree leaf |

Private note/encryption keys stay in storage and are not exposed through the SDK.

## Logging & Diagnostics

The SDK integrates with the `tracing` ecosystem. You can initialize a default tracing subscriber for native binaries/tests:

```rust
use stellar_private_payments_sdk::init_tracing;

fn main() {
    // Installs a subscriber logging to stdout based on RUST_LOG env var
    init_tracing();
}
```

## Browser / WASM

See [`../web/README.md`](../web/README.md). JS method names align with Rust where possible (`operationalFeed`, `recipientLookup`, `userPublicKeys`, `isRegistered`).

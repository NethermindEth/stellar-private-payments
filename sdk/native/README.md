# Stellar Private Payments — Rust SDK (`stellar-private-payments`)

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
use stellar_private_payments::{
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
        as Box<dyn stellar_private_payments::Signer>,
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

## Examples

The `examples/` directory demonstrates the blocking SDK API surface. Each example uses the shared `examples/common` bootstrap and exits 0 with instructions when a prerequisite is missing.

All examples run in **release mode**. The transact examples resolve circuit
artifacts from `target/circuits-artifacts/release`, which only a release build
populates, so a debug build fails with a misleading "run `cargo build -p
circuits`" error even after you have built the circuits correctly.

| Example | What it shows | Run |
|---------|---------------|-----|
| `account_pool` | Account identity, registration, keys, portfolio, and pool state reads | `cargo run --release --example account_pool` |
| `sync` | Deployment-level sync, background sync, and operational feed | `cargo run --release --example sync` |
| `estimate` | Transaction-count estimation and plan introspection | `cargo run --release --example estimate` |
| `deposit` | Full proving + submission of a deposit | `cargo run --release --example deposit` |
| `transfer` | Private transfer to a recipient | `SPP_RECIPIENT_ADDRESS="G..." cargo run --release --example transfer` |
| `withdraw` | Withdraw from the pool to a public Stellar address | `cargo run --release --example withdraw` |

See [`examples/SETUP.md`](examples/SETUP.md) for the complete environment setup walkthrough (creating testnet accounts, funding, onboarding, and release-mode run commands). See the header comment in each example for its exact env-var contract. The shared contract is:

| Variable | Default | Required by |
|----------|---------|-------------|
| `STELLAR_SECRET_KEY` | — | `account_pool`, `estimate`, `deposit`, `transfer`, `withdraw` |
| `SPP_RPC_URL` | `https://soroban-testnet.stellar.org` | all examples |
| `SPP_WALLET_PATH` | `./spp-example-wallet.sqlite` | all examples |
| `SPP_DEPLOYMENT_JSON` | `deployments/testnet/deployments.json` | all examples |
| `SPP_POOL_CONTRACT_ID` | first enabled pool in deployment config | account/pool/transact examples |
| `SPP_CIRCUIT_KEYS_DIR` | `deployments/testnet/circuit_keys` | `deposit`, `transfer`, `withdraw` |
| `SPP_CIRCUIT_ARTIFACTS_DIR` | `target/circuits-artifacts/{debug\|release}` | `deposit`, `transfer`, `withdraw` |
| `SPP_AMOUNT_STROOPS` | `10000000` (1 XLM) | `estimate`, `deposit`, `transfer`, `withdraw` |
| `SPP_BOOTNODE_URL` | `https://bootnode.dev-nethermind.xyz` | all examples (set to an empty string to disable the fallback) |
| `SPP_NETWORK_PASSPHRASE` | derived from `network` in `deployments.json` | account/pool/transact examples |
| `SPP_RECIPIENT_ADDRESS` | — for `transfer`; the wallet's own address for `withdraw` | `transfer`; also read by `withdraw` |
| `SPP_RECIPIENT_NOTE_KEY` + `SPP_RECIPIENT_ENCRYPTION_KEY` | — | `transfer`, as an alternative to `SPP_RECIPIENT_ADDRESS` (0x-prefixed 32-byte keys, skipping the registry lookup) |
| `SPP_REGISTER` | unset | `account_pool` (set to `1` to publish privacy keys on-chain — this writes a transaction) |
| `SPP_VERBOSE_PLAN` | unset | `deposit` (set to `1` for per-step prove/simulate/sign/submit logs) |

> **`SPP_RECIPIENT_ADDRESS` governs `withdraw` too.** `withdraw` defaults to
> self-withdrawal, but if this variable is still exported from a `transfer`
> run it silently becomes the withdrawal destination. Unset it (or set it to
> the wallet's own address) before running `withdraw`. The example prints
> `(Using self-withdrawal; ...)` when the destination is the wallet itself —
> if that line is absent, the funds are going somewhere else.

### Prerequisites

- The examples target the checked-in **testnet** deployment by default.
- Transact examples (`deposit`, `transfer`, `withdraw`) need circuit artifacts. Build them first with `cargo build -p circuits --release`.
- Transact examples need a **funded, onboarded** testnet account: onboard the wallet (for example with the `spp` CLI) and ensure the account holds the pool asset.
- **Allowlist pools require ASP membership.** The default testnet pool (native XLM) carries only the `blocklist` flag and needs no membership setup. The second testnet pool (EURC) adds the `allowlist` flag; before a wallet can `deposit` or `transfer` through it, the pool admin must insert each participant's ASP membership leaf into the `asp_membership` contract. Without it those examples fail even though the account is funded, onboarded, and circuit-ready. See [ASP membership for allowlist pools](examples/SETUP.md#asp-membership-for-allowlist-pools).
- These prerequisite classes print a skip message and exit 0 rather than failing: a missing `STELLAR_SECRET_KEY`, a wallet without privacy keys, missing circuit artifacts, and an RPC retention gap. Other misconfiguration — an unreadable `SPP_DEPLOYMENT_JSON`, an unopenable `SPP_WALLET_PATH`, or a `SPP_POOL_CONTRACT_ID` that is not in the deployment config — surfaces as a hard error, because those paths propagate rather than exiting early.

### Sync caveat: the checked-in deployment has a ~7-day shelf life

The public Soroban testnet RPC serves a rolling window of 120 960 ledgers —
about **7 days** at ~5 s per ledger. Every example syncs from the pool's
`deploymentLedger`, so roughly one week after the contracts were last deployed
that ledger falls out of the window and a wallet with no prior sync history can
no longer catch up. Check the remaining margin before you start:

```bash
jq -r '.pools[0].deploymentLedger' deployments/testnet/deployments.json
curl -s -X POST https://soroban-testnet.stellar.org \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | jq '.result.oldestLedger'
```

If `deploymentLedger` is below `oldestLedger`, the deployment has expired.

When that happens the examples exit 0 with an explanation and a remedy list
rather than a raw JSON-RPC error — but they **cannot** sync, so the graceful
message is not a workaround. Actually running them then requires a bootnode
holding the missing range (see [Local bootnode](examples/SETUP.md#local-bootnode))
or a fresh contract deployment. Setting `SPP_RPC_URL` to a full-history RPC also
works if you have one.

Already-synced wallets are unaffected: they sync incrementally and never need
the missing history. This is specifically a first-run problem.

## Blocking API

For CLI and synchronous hosts, use `stellar_private_payments::blocking`:

```rust
use stellar_private_payments::blocking::{Client, Account};

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
| `Account::derive_asp_user_leaf()` | ASP membership tree leaf from stored keys |
| `crypto::derive_asp_user_leaf(note, blinding)` | Same leaf from explicit inputs (no session) |

Private note/encryption keys stay in storage and are not exposed through the SDK.

## Logging & Diagnostics

The SDK emits `tracing` spans and events but does **not** install a subscriber —
that is the consumer's responsibility, so the library stays free of a
`tracing-subscriber` dependency. Install one in your binary/tests, and include
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

### Intermediate SDK Logs
Intermediate transaction lifecycle steps (simulating, submitting, confirming) are instrumented at the `info!` level. Every operation uses an inherited or generated `correlation_id` so that the entire blocking call trace (e.g., `pool.deposit()`) can be correlated end-to-end. To view these steps, ensure your tracing subscriber or `TelemetryConfig` filters include at least `info` for `stellar_private_payments`.

## Browser / WASM

See [`../web/README.md`](../web/README.md). JS method names align with Rust where possible (`operationalFeed`, `recipientLookup`, `userPublicKeys`, `isRegistered`).

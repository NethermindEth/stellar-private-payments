# SDK Examples Setup Guide

This guide walks through the one-time setup needed to run the examples in
[`sdk/client/examples/`](./). It targets the checked-in **Stellar testnet**
deployment by default.

The examples use a shared environment-variable contract defined in
[`common/mod.rs`](./common/mod.rs). All transact examples (`deposit`,
`transfer`, `withdraw`) must be run in **release mode** so they resolve circuit
artifacts from `target/circuits-artifacts/release`.

## Table of contents

1. [Prerequisites](#prerequisites)
2. [Create two testnet accounts](#create-two-testnet-accounts)
3. [Fund the accounts](#fund-the-accounts)
4. [Build circuit artifacts](#build-circuit-artifacts)
5. [Onboard the wallets](#onboard-the-wallets)
6. [Local bootnode](#local-bootnode)
7. [ASP membership for allowlist pools](#asp-membership-for-allowlist-pools) (EURC pool only — skip for the default XLM pool)
8. [Environment variables](#environment-variables)
9. [Run the examples](#run-the-examples)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- A working Rust toolchain with `cargo`.
- The Stellar CLI (`stellar`) installed and on your `PATH`, **version 27.0 or
  later**. The `spp onboard --register` command uses `stellar tx sign
  --auto-sign`, which is not available in older releases. Run `stellar
  --version` to check.
- The `spp` CLI uses `stellar keys` to resolve accounts and sign the
  key-derivation message.
- Network access to the public Soroban testnet RPC endpoint
  (`https://soroban-testnet.stellar.org`).

## Create two testnet accounts

Most examples need one funded, onboarded account. The `transfer` example needs a
second account as the recipient, and the easiest path is to use a registered
Stellar address looked up via `SPP_RECIPIENT_ADDRESS`.

Create two keypairs and store them as aliases in the Stellar CLI. If `alice`
or `bob` already exist, pick any unused aliases and use those everywhere below
(e.g., `alice_spp` and `bob_spp`):

```bash
stellar keys generate alice --network testnet
stellar keys generate bob   --network testnet
```

> If you prefer not to use the Stellar CLI, you can generate keypairs with the
> [Stellar Laboratory](https://laboratory.stellar.org/) and export the secret
> keys. The examples themselves read the raw secret from `STELLAR_SECRET_KEY`,
> so any testnet keypair works.

Record the public addresses:

```bash
stellar keys address alice
stellar keys address bob
```

Also extract the raw secret keys for use with the examples:

```bash
stellar keys secret alice
stellar keys secret bob
```

Export Alice's secret in your shell (the examples sign with it directly):

```bash
export STELLAR_SECRET_KEY="S..."   # Alice's secret key
export SPP_RECIPIENT_ADDRESS="G..." # Bob's public address
```

> Use a throwaway testnet key only — never export a secret that controls real
> mainnet funds.

## Fund the accounts

Request testnet XLM from friendbot for both addresses:

```bash
# Replace with the actual public addresses from the previous step.
curl "https://friendbot.stellar.org/?addr=<ALICE_ADDRESS>"
curl "https://friendbot.stellar.org/?addr=<BOB_ADDRESS>"
```

## Build circuit artifacts

The `deposit`, `transfer`, and `withdraw` examples build zero-knowledge proofs,
so they need the compiled proving keys and circuit artifacts. Always build in
release mode:

```bash
cargo build -p circuits --release
```

This writes wasm and r1cs artifacts under
`target/circuits-artifacts/release/` and uses the committed proving keys in
`deployments/testnet/circuit_keys/`.

## Onboard the wallets

The examples require the local SQLite wallet to contain derived privacy keys.
Use the `spp` CLI to onboard each account. From the repository root:

```bash
# Onboard Alice's wallet. The default data dir writes the SQLite wallet to
# ~/.local/share/stellar-private-payments/spp.db.
cargo run --release -p stellar-private-payments-cli -- onboard \
  --account alice --accept --register

# Onboard Bob's wallet into a separate database so the examples can use it as a
# recipient without overwriting Alice's wallet.
cargo run --release -p stellar-private-payments-cli -- onboard \
  --account bob --accept --register \
  --data-dir ./spp-bob-wallet
```

What `spp onboard` does:

1. Accepts the disclaimer.
2. Signs the key-derivation message via `stellar keys` (the secret never enters
   the `spp` process).
3. Derives and stores the privacy note/encryption keys and ASP blinding.
4. Optionally registers the public keys on-chain so other accounts can transfer
   to this address without knowing the raw keys.

> The `spp` CLI and the examples use different default wallet paths. The `spp`
> CLI uses the path above; the examples default to `./spp-example-wallet.sqlite`.
> Set `SPP_WALLET_PATH` to the actual wallet when running each example, as shown
> in the next section.

### Non-interactive onboarding

For unattended or CI setups, pass the bootnode and explorer URLs explicitly so
`spp onboard` does not prompt:

```bash
cargo run --release -p stellar-private-payments-cli -- onboard \
  --account alice --accept --register \
  --bootnode-url http://127.0.0.1:8080 \
  --explorer-url https://stellar.expert/explorer/testnet
```

If you are using the public bootnode, replace the `--bootnode-url` value with
`https://bootnode.dev-nethermind.xyz` or omit the flag and set
`SPP_BOOTNODE_URL` later for the examples.

## Local bootnode

The checked-in testnet deployment is older than the public Soroban RPC retention
window. A local bootnode is the most reliable way to keep the examples' inline
sync working:

### Docker (recommended)

```bash
cd tools/bootnode
docker compose -f docker-compose.yml -f docker-compose.no-https.yml up --build
```

The local bootnode URL is `http://127.0.0.1:8080`. Check health with:

```bash
curl http://127.0.0.1:8080/healthz
```

### Cargo

```bash
cargo build --manifest-path tools/bootnode/Cargo.toml
export DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/bootnode'
# Start Postgres first, then:
./tools/bootnode/target/debug/bootnode \
  --dev --insecure-http --bind 127.0.0.1:8080 \
  --upstream-rpc-url https://soroban-testnet.stellar.org \
  --database-url "$DATABASE_URL"
```

Use the local bootnode during onboarding (`--bootnode-url
http://127.0.0.1:8080`) and when running the examples by setting
`SPP_BOOTNODE_URL=http://127.0.0.1:8080`.

## ASP membership for allowlist pools

> **You can skip this section for the default pool.** The default testnet pool
> (native XLM) is configured with only a `blocklist` policy flag, so it needs
> no ASP membership setup. This step applies only to the second testnet pool
> (EURC), which adds an `allowlist` flag — select it with
> `SPP_POOL_CONTRACT_ID=CAJJT5YV4BMFTHEOO5FGO2G56TEJKM4G4FW7FS4DYBLLLLHSAYUZWT74`.

Before a wallet can `deposit` or `transfer` through an allowlist pool, the
pool admin must insert that wallet's ASP membership leaf into the
`asp_membership` contract.

1. Obtain the ASP membership contract ID from the deployment config:

   ```bash
   jq -r '.asp_membership' deployments/testnet/deployments.json
   ```

2. Compute the leaf for each account. The examples do not expose this directly,
   but the SDK provides `Account::derive_asp_user_leaf`. The shortest route is a
   throwaway example file under `sdk/client/examples/`, reusing the shared
   bootstrap so it picks up the same `SPP_WALLET_PATH` / `STELLAR_SECRET_KEY`
   environment as everything else:

   ```rust
   mod common;

   fn main() -> Result<(), Box<dyn std::error::Error>> {
       let config = common::load_contract_config()?;
       let storage = common::open_storage()?;
       let client = common::build_readonly_client(storage, config)?;
       let account = common::build_account(&client)?;
       common::require_onboarded(&account)?;
       println!("{}", account.derive_asp_user_leaf()?);
       Ok(())
   }
   ```

   Run it with `cargo run --release --example <name>`, once per wallet with that
   wallet's `SPP_WALLET_PATH` and `STELLAR_SECRET_KEY` exported, then delete the
   file. Note there is no `Client::account_for_secret`; an account session is
   opened with `Client::account(&address, signer)`, which is what
   `common::build_account` wraps.

3. As the pool admin, invoke `insert_leaf` once per participant:

   ```bash
   ASP_MEMBERSHIP=$(jq -r '.asp_membership' deployments/testnet/deployments.json)
   stellar contract invoke --id "$ASP_MEMBERSHIP" \
     --source <ADMIN_IDENTITY> --network testnet -- insert_leaf --leaf <LEAF_HEX>
   ```

## Environment variables

The examples share a single env-var contract. Only `STELLAR_SECRET_KEY` is
required by most examples; everything else has a sensible default.

| Variable | Default | Required by |
| --- | --- | --- |
| `STELLAR_SECRET_KEY` | — | `account_pool`, `estimate`, `deposit`, `transfer`, `withdraw` |
| `SPP_RPC_URL` | `https://soroban-testnet.stellar.org` | all examples |
| `SPP_WALLET_PATH` | `./spp-example-wallet.sqlite` | all examples |
| `SPP_DEPLOYMENT_JSON` | `deployments/testnet/deployments.json` | all examples |
| `SPP_POOL_CONTRACT_ID` | first enabled pool in deployment config | account/pool/transact examples |
| `SPP_CIRCUIT_KEYS_DIR` | `deployments/testnet/circuit_keys` | `deposit`, `transfer`, `withdraw` |
| `SPP_CIRCUIT_ARTIFACTS_DIR` | `target/circuits-artifacts/release` in release builds | `deposit`, `transfer`, `withdraw` |
| `SPP_AMOUNT_STROOPS` | `10000000` (1 XLM) | `estimate`, `deposit`, `transfer`, `withdraw` |
| `SPP_BOOTNODE_URL` | `https://bootnode.dev-nethermind.xyz` | all examples |
| `SPP_NETWORK_PASSPHRASE` | derived from `network` in `deployments.json` | account/pool/transact examples |
| `SPP_RECIPIENT_ADDRESS` | — for `transfer`; the wallet's own address for `withdraw` | `transfer` (or use `SPP_RECIPIENT_NOTE_KEY` + `SPP_RECIPIENT_ENCRYPTION_KEY`); **also read by `withdraw`** |
| `SPP_REGISTER` | unset | `account_pool` (set to `1` to call `register_public_keys`) |
| `SPP_VERBOSE_PLAN` | unset | `deposit` (set to `1` for step-by-step logs) |

> `SPP_BOOTNODE_URL` is read directly by the examples and overrides the default
> public bootnode. Every example that opens a client reads it, not just `sync`.
> Set it to an empty string to disable the bootnode fallback entirely. It is
> independent of the bootnode URL stored in the wallet by `spp onboard`; if you
> onboarded with a local bootnode, set the same URL here when running the
> examples.

> `SPP_NETWORK_PASSPHRASE` only needs setting if `deployments.json` names a
> network other than `testnet`, `public`, or `futurenet`; those three are mapped
> automatically. An unrecognized network fails with a message telling you to set
> it explicitly.

The most convenient way to run the examples is to export the variables you need
in your shell. Use the wallet paths that match the onboarding commands above:

```bash
# Alice's wallet (created by the default spp CLI data dir).
export STELLAR_SECRET_KEY="S..."
export SPP_WALLET_PATH="$HOME/.local/share/stellar-private-payments/spp.db"
export SPP_RECIPIENT_ADDRESS="G..."  # Bob's public address
```

For the few steps that use Bob's wallet:

```bash
export STELLAR_SECRET_KEY="S..."     # Bob's secret key
export SPP_WALLET_PATH="./spp-bob-wallet/spp.db"
```

## Run the examples

All examples are built and run in **release mode**. Each command below assumes
Alice's wallet path; adjust `SPP_WALLET_PATH` if you onboarded elsewhere:

```bash
# Read-only account and pool state.
cargo run --release --example account_pool

# Deployment-level sync and operational feed.
cargo run --release --example sync

# Transaction-count estimation and plan introspection.
cargo run --release --example estimate

# Deposit 1 XLM into the pool (proving + submission).
cargo run --release --example deposit

# Private transfer to Bob's registered address.
SPP_RECIPIENT_ADDRESS="<BOB_ADDRESS>" cargo run --release --example transfer

# Withdraw 1 XLM back to the wallet's public address. `env -u` clears the
# recipient exported for `transfer` above, which `withdraw` would otherwise
# use as the withdrawal destination.
env -u SPP_RECIPIENT_ADDRESS cargo run --release --example withdraw
```

Run order for a full demo:

1. `account_pool` to confirm the wallet is onboarded and read the pool config.
2. `sync` to catch the wallet state up to chain tip.
3. `deposit` — **run it twice**, so the wallet holds two notes.
4. `estimate` to inspect the plan cursor after the deposit.
5. `transfer` to send private value to the recipient (spends one note).
6. `withdraw` to move funds back to a public address (spends the other).

> **Each spend consumes a note.** With the default `SPP_AMOUNT_STROOPS`
> (1 XLM), one `deposit` creates exactly one 1-XLM note, and `transfer` and
> `withdraw` each consume one. A single `deposit` therefore leaves nothing for
> `withdraw`, which then prints `Skipping: no spendable notes in the selected
> pool.` and exits 0 — a pass that demonstrated nothing. Run `deposit` once per
> spend you intend to make, or re-run it before `withdraw`.

> `transfer` and `withdraw` require spendable notes. If the wallet has none,
> they print a skip message and exit 0. Run `deposit` first.

> **Timing:** `deposit`, `transfer`, and `withdraw` invoke the local Groth16
> prover. Measured on testnet, a single-transaction operation completes in
> roughly 5–10 seconds end to end: about 2 seconds of proving, with most of the
> remainder spent waiting for the ledger to close. If one of these runs takes
> substantially longer, suspect the build rather than the prover —
> `cargo run` performs build work before the example starts, and `--quiet`
> hides it. Run `cargo build --release -p stellar-private-payments-sdk
> --examples` first to separate build time from run time.

> **`withdraw` and `SPP_RECIPIENT_ADDRESS`:** the run order above exports
> `SPP_RECIPIENT_ADDRESS` for `transfer`, and `withdraw` reads the *same*
> variable. If it is still exported, `withdraw` sends the funds to that address
> instead of back to your own account. Unset it first:
>
> ```bash
> env -u SPP_RECIPIENT_ADDRESS cargo run --release --example withdraw
> ```
>
> `withdraw` prints `(Using self-withdrawal; funds will return to the wallet's
> public address.)` when the destination is your own account. If that line is
> missing, the funds are going elsewhere.

## Troubleshooting

### Missing privacy keys

If an example prints:

```text
Skipping: wallet at ./spp-example-wallet.sqlite does not contain privacy keys ...
Onboard the wallet first (e.g. with the `spp` CLI) and re-run.
```

Run `spp onboard --account <alias> --accept` for the account you are using.

### Missing circuit artifacts

If a transact example prints:

```text
Run `cargo build -p circuits` to generate circuit keys and artifacts.
```

Run:

```bash
cargo build -p circuits --release
```

### Retention gap / sync gap — the deployment expires after ~7 days

The public Soroban testnet RPC serves a rolling window of 120 960 ledgers,
about **7 days** at ~5 s per ledger. Every example syncs from the pool's
`deploymentLedger`, so roughly a week after the contracts were last deployed
that ledger drops out of the window and a wallet with no prior sync history can
no longer catch up. This is a scheduled expiry, not an intermittent glitch.

Check the remaining margin before you start:

```bash
jq -r '.pools[0].deploymentLedger' deployments/testnet/deployments.json
curl -s -X POST https://soroban-testnet.stellar.org \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | jq '.result.oldestLedger'
```

If `deploymentLedger` is below `oldestLedger`, the deployment has expired.

Past the cliff the examples exit 0 with a retention-gap note and a remedy list.
Two distinct underlying errors produce it — with no bootnode configured the SDK
reports `RPC sync gap: main RPC lacks history ...`, and with one configured that
cannot serve the range you get:

```text
bootnode indexer: jsonrpc error: -32602 - unsupported filters (requested startLedger=..., cursor=<none>)
```

Both are infrastructure limits, not example-code faults. **The graceful message
is not a workaround** — the examples still cannot sync, so they cannot show you
real state. To actually run them you need one of:

- A bootnode holding the missing range — see [Local bootnode](#local-bootnode) —
  pointed at by both `spp onboard --bootnode-url` and `SPP_BOOTNODE_URL`.
- A full-history `SPP_RPC_URL`.
- A fresh contract deployment, which resets the 7-day clock.

Retrying later does **not** help: the window moves forward, not back.

An already-synced wallet is unaffected, because it syncs incrementally and never
needs the missing history. This is specifically a first-run problem.

> **Implementation note for maintainers:** the examples classify this condition
> by matching substrings in the error text (`sync gap`, `retention`,
> `unsupported filters`, `bootnode indexer`) in
> `common::is_retention_gap_error`. That is deliberate, not an oversight. The
> robust alternative is a dedicated error variant in the SDK, but `sdk/client`
> is consumed by `cli`, `sdk/tests`, and `sdk/web`, so the typed-error change
> was kept out of scope here. If you add a retention-gap error type to the SDK,
> switch these detectors to match on it.

### Insufficient funds

`deposit` checks that the account holds enough of the pool asset. If the
balance is too low, fund the address with testnet XLM via friendbot and retry.

### `NoSpendableNotes` from `deposit` (fixed)

Earlier versions of the `deposit` example called `pool.estimate(amount)` before
`pool.deposit(amount)` to print the expected transaction count, which failed
with `NoSpendableNotes` on a wallet that had never deposited. `estimate` is a
*spend*-side estimator: it loads the wallet's spendable notes and asks the
planner to cover the amount from them. A deposit is input-only and needs no
existing notes.

The example now calls `pool.prepare_deposit(amount)` and reads
`plan.tx_count()`, which is the deposit-shaped equivalent and takes no wallet at
all. A first-time deposit on an empty wallet works. If you see this error, your
checkout predates the fix.

# stellar-spp

Stellar CLI plugin for private payments. Provides full feature parity with the browser UI from the terminal.

The binary is named `stellar-spp`, which means the Stellar CLI auto-discovers it and exposes all commands under `stellar spp <command>`.

## Prerequisites

- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli) installed and in `PATH`
- At least one Stellar identity configured via `stellar keys generate` or `stellar keys add`
- Contracts deployed (see `scripts/deployments.json`)

### Circuit Artifacts

Proof generation requires compiled circuit artifacts. Build them before the first proof-generating command (`deposit`, `withdraw`, `transfer`):

```bash
# From the workspace root
BUILD_TESTS=1 cargo build -p circuits
```

This produces:
- `policy_test.wasm` and `policy_test.r1cs` (compiled by the circuits build script)
- `scripts/testdata/policy_test_proving_key.bin` (pre-generated, checked into the repo)

The CLI's `build.rs` automatically locates these artifacts in the build tree and embeds them into the binary via `include_bytes!()`.

## Building

```bash
cargo build -p stellar-spp
# or for a release build:
cargo build -p stellar-spp --release
```

The binary is output to `target/{debug,release}/stellar-spp`. Symlink or copy it somewhere in your `PATH` for `stellar spp` auto-discovery:

```bash
cp target/release/stellar-spp ~/.cargo/bin/
```

## Quick Start

```bash
# 1. Initialize: loads contract addresses from deployments.json, creates local data store, runs initial sync
stellar spp init

# 2. Derive and inspect your ZK keys
stellar spp keys show --source alice

# 3. Register your public keys on-chain (required before receiving transfers)
stellar spp register --source alice

# 4. Deposit 1000 stroops into the privacy pool
stellar spp deposit 1000 --source alice

# 5. Check your balance
stellar spp status --source alice

# 6. Transfer 500 stroops privately to bob
stellar spp transfer 500 --to bob --source alice

# 7. Withdraw 300 stroops back to your Stellar account
stellar spp withdraw 300 --to alice --source alice

# 8. Scan for incoming notes (e.g., notes sent to you by others)
stellar spp notes scan --source alice
```

## Command Reference

All commands accept the global flags `--network <name>` (default: `testnet`) and `--pool <name>` (selects a named pool). These can also be set via the `STELLAR_NETWORK` and `STELLAR_SPP_POOL` environment variables.

All identity flags (`--source`, `--account`, `--to`, `--new-admin`) accept Stellar CLI identity names (e.g., `alice`, `admin`) -- never raw keys.

### Infrastructure

| Command | Description |
|---------|-------------|
| `stellar spp init` | Load deployment config from `deployments.json`, create the local data store, and run an initial event sync |
| `stellar spp sync` | Incremental sync: fetch new on-chain events since the last sync |
| `stellar spp status [--source <id>]` | Show sync status, pool statistics, and (optionally) the balance for an identity |

### Key Management

| Command | Description |
|---------|-------------|
| `stellar spp keys derive --source <id>` | Derive BN254 note keypair and X25519 encryption keypair from a Stellar identity |
| `stellar spp keys show --source <id>` | Display the derived keys |
| `stellar spp register --source <id>` | Publish the identity's note public key and encryption public key on-chain via a `PublicKeyEvent` |

### Transactions

| Command | Description |
|---------|-------------|
| `stellar spp deposit <amount> --source <id>` | Deposit `<amount>` stroops from the Stellar account into the privacy pool, creating a shielded note |
| `stellar spp withdraw <amount> --to <id> --source <id>` | Withdraw `<amount>` stroops from the pool to the `--to` Stellar account |
| `stellar spp transfer <amount> --to <id> --source <id>` | Privately transfer `<amount>` stroops to another registered user within the pool |

### Note Management

| Command | Description |
|---------|-------------|
| `stellar spp notes list --source <id>` | List all known notes (spent and unspent) for an identity |
| `stellar spp notes scan --source <id>` | Decrypt on-chain encrypted outputs to discover notes addressed to this identity |
| `stellar spp notes export <note-id>` | Export a note (by commitment hex) to JSON on stdout |
| `stellar spp notes import <file>` | Import a note from a JSON file |

### Pool Management

| Command | Description |
|---------|-------------|
| `stellar spp pool add <name> [--pool-id <C...> --asp-membership <C...> --asp-non-membership <C...> --verifier <C...>]` | Add a pool from `deployments.json` or explicit contract IDs |
| `stellar spp pool ls` | List pools for the current network, showing which is the default |
| `stellar spp pool rm <name>` | Remove a pool and its local data |
| `stellar spp pool use <name>` | Set the default pool for the current network |

### ASP Administration

| Command | Description |
|---------|-------------|
| `stellar spp admin add-member --account <id> --source <admin>` | Derive the member's note public key, compute the membership leaf, and insert it into the ASP Membership Merkle tree |
| `stellar spp admin remove-member --account <id> --source <admin>` | Remove a member (not yet supported by the on-chain contract) |
| `stellar spp admin update-admin --new-admin <id> [--contract <C...>] --source <admin>` | Transfer admin rights on an ASP contract |

## Architecture

### Identity and Key Derivation

The CLI never handles raw keys directly. Every identity flag resolves through the Stellar CLI:

```
stellar keys secret <name>  -->  S... secret key  -->  32-byte Ed25519 seed
```

From the Ed25519 seed, two deterministic key derivations are performed:

```
Ed25519 seed
  |
  +-- sign("Privacy Pool Spending Key [v1]")  --> SHA-256 --> Fr::from_le_bytes_mod_order
  |   = BN254 note private key
  |   --> Poseidon2(privKey, 0, domain=3)  = note public key
  |
  +-- sign("Sign to access Privacy Pool [v1]")  --> SHA-256 --> X25519 StaticSecret
      = encryption private key
      --> X25519 PublicKey  = encryption public key
```

Ed25519 signatures are deterministic (RFC 8032), so the CLI derives identical keys to the Freighter browser wallet for the same Stellar account.

### Stellar CLI Delegation

All network operations delegate to the `stellar` CLI via subprocess calls. This avoids the need for reqwest/tokio and ensures compatibility with the user's existing Stellar configuration (network settings, key storage).

| Operation | Stellar CLI command |
|-----------|-------------------|
| Resolve identity address | `stellar keys address <name>` |
| Resolve identity secret | `stellar keys secret <name>` |
| Fetch contract events | `stellar events --id <contract> --start-ledger <N> --count 1000 --output json` |
| Read contract state | `stellar contract invoke --id <contract> --send no -- <function>` |
| Submit transaction | `stellar contract invoke --id <contract> --source-account <id> -- <function> <args>` |

### Local State (JSON)

State is stored per-pool as JSON files under the platform config directory (`~/Library/Application Support/stellar/spp/` on macOS, `~/.config/stellar/spp/` on Linux):

```
{network}/
  config.toml                   # NetworkConfig: default_pool name
  pools/
    {pool_name}.toml            # DeploymentConfig: contract IDs, network, admin
    {pool_name}.json            # Pool data store (synced events, notes, keys)
```

Each pool's JSON data store contains:

| Key | Purpose |
|-----|---------|
| `sync_metadata` | Last synced ledger and cursor per contract type |
| `pool_leaves` | Pool commitment Merkle tree leaves (index, commitment hex, ledger) |
| `nullifiers` | Spent nullifier set |
| `encrypted_outputs` | Encrypted note data from `NewCommitmentEvent` events |
| `asp_leaves` | ASP membership Merkle tree leaves from `LeafAdded` events |
| `user_notes` | Decrypted/created notes with amount, blinding, spent status |
| `registered_keys` | Public key registry from `PublicKeyEvent` events |

Old flat-file configs (`{network}.toml`/`.json`) are automatically migrated to the per-pool layout as a pool named `default`.

### Proof Generation

The CLI embeds the compiled circuit artifacts (WASM, R1CS) and the pre-generated Groth16 proving key directly into the binary. Proof generation follows the same pipeline as `e2e-tests/src/tests/utils.rs`:

1. Build a `TxCase` with input notes (from local store) and output notes (freshly generated)
2. Place input commitments in the pool Merkle tree and compute proofs
3. Compute membership proofs against the ASP Merkle tree
4. Compute non-membership proofs against the ASP sparse Merkle tree
5. Assemble all circuit signals (root, nullifiers, commitments, public amount, extDataHash, membership/non-membership proofs)
6. Build the Circom circuit, generate a Groth16 proof, and self-verify
7. Serialize the proof and external data, then submit via `stellar contract invoke`

### Cryptographic Primitives

| Primitive | Usage | Domain |
|-----------|-------|--------|
| `Poseidon2(a, b, c, domain=1)` | Commitment: `hash(amount, pubkey, blinding)` | Leaf/commitment |
| `Poseidon2(a, b, c, domain=2)` | Nullifier: `hash(commitment, pathIndices, signature)` | Nullifier |
| `Poseidon2(a, b, domain=3)` | Public key: `hash(privateKey, 0)` | Key derivation |
| `Poseidon2(a, b, c, domain=4)` | Signature: `hash(privateKey, commitment, merklePath)` | Signature |
| `Poseidon2(a, b)` (compression) | Merkle tree internal nodes (feed-forward mode) | Merkle tree |
| `X25519-XSalsa20-Poly1305` | Note encryption (amount + blinding for recipient) | Off-chain |
| `Keccak256 mod BN256` | ExtDataHash binding proof to transaction parameters | On-chain |

## Source Layout

```
cli/
  Cargo.toml               # Crate manifest, dependencies
  build.rs                  # Copies circuit artifacts for embedding
  src/
    main.rs                 # Entry point, clap dispatch, command handlers
    cli.rs                  # Clap derive structs for all commands and flags
    config.rs               # Deployment config, pool management, path resolution, migration
    db.rs                   # JSON file-backed storage for pool state
    stellar.rs              # Subprocess wrapper for `stellar` CLI calls
    keys.rs                 # Stellar identity resolution, BN254/X25519 derivation
    crypto.rs               # Poseidon2 hashing, scalar conversions, note encryption
    merkle.rs               # In-memory Merkle tree reconstruction from local state
    sync.rs                 # Event fetching, incremental sync engine
    proof.rs                # Circuit input assembly, Groth16 proving (embedded artifacts)
    transaction.rs          # Deposit/withdraw/transfer: proof gen + contract invocation
    notes.rs                # Note scanning (decrypt encrypted outputs), import/export
    admin.rs                # ASP admin commands (add-member, update-admin)
    display.rs              # Output formatting (tables, key display)
```

## Configuration

On `stellar spp init`, the CLI reads `scripts/deployments.json` from the workspace and saves a pool config (e.g. `.../{network}/pools/default.toml`):

```toml
network = "testnet"
deployer = "GBBM2..."
admin = "GBBM2..."
pool = "CAIGQ..."
asp_membership = "CDWUK..."
asp_non_membership = "CCX5L..."
verifier = "CCIQN..."
initialized = true
```

Subsequent commands load from this file. Pool resolution follows this order:

1. `--pool <name>` flag
2. `STELLAR_SPP_POOL` environment variable
3. Default pool from `.../{network}/config.toml`

To manage multiple pools on the same network (e.g. different deployments), use the `pool` subcommands:

```bash
stellar spp pool add staging --pool-id CABC... --asp-membership CDEF... --asp-non-membership CGHI... --verifier CJKL...
stellar spp pool use staging
stellar spp pool ls
```

## Note Format (Import/Export)

Notes are exported and imported as JSON:

```json
{
  "id": "a1b2c3...",
  "owner": "d4e5f6...",
  "private_key": "0102030405...",
  "blinding": "0a0b0c0d...",
  "amount": 1000,
  "leaf_index": 42,
  "spent": 0,
  "is_received": 1,
  "ledger": 12345678
}
```

- `id`: Commitment hash (big-endian hex) -- serves as the unique identifier
- `owner`: Note public key (big-endian hex)
- `private_key`: BN254 note private key (little-endian hex)
- `blinding`: Blinding factor (little-endian hex)
- `amount`: Value in stroops
- `leaf_index`: Position in the pool Merkle tree

## License

Apache-2.0

# Contributor's guide

## Commit signing

Enable [commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

```sh
git config commit.gpgsign true
```

## Documentation

Unified project documentation is available at https://nethermindeth.github.io/stellar-private-payments/docs/

## Communication and environment notes

- External contributors should mention their PR in the project [LinkedIn group](https://www.linkedin.com/groups/18809039/). PRs from forks are not reviewed without this notice because we need to see a human behind the contribution.
- Active development discussions happen in the [Telegram group](https://t.me/stellar_privacy). If you have technical questions you should ask them there.
- You may need to reset local browser storage from time to time. [Bootnode](https://github.com/NethermindEth/stellar-private-payments/issues/169) support is not available yet, and contracts are redeployed during development.

## Project Structure

```
stellar-private-payments/
├── app/                        # Web application (see app/README.md, app/ARCHITECTURE.md)
│   ├── js/                     # JavaScript frontend code (web interface)
│   │   ├── ui/                 # UI components
│   │   ├── admin.js            # Admin UI entry
│   │   ├── ui.js               # Main UI entry
│   │   ├── disclosure.js       # Selective disclosure UI entry
│   │   ├── app-storage.js      # App-only persistence (settings, op history)
│   │   ├── db-locked.js        # DB-locked (storage in use by another tab) modal
│   │   ├── wallet.js           # Freighter connect/watch/sign UX
│   │   ├── wasm-facade.js      # Runtime facade over stellar-private-payments-sdk-web
│   │   └── sw.js               # Service worker
│   ├── css/                    # Stylesheets
│   ├── assets/                 # Static assets (logo, favicon)
│   ├── index.html              # Main web application entry (includes the Disclosure view)
│   └── admin.html              # Admin entry
├── sdk/                        # Platform-agnostic Rust SDK crates
│   ├── web/                    # Browser npm package (WASM, workers, bundled circuits)
│   ├── disclosure/             # Selective disclosure
│   ├── prover/                 # Proving flows
│   ├── state/                  # Storage and indexer
│   ├── stellar/                # Stellar/Soroban client
│   ├── tx-planner/             # Transaction planning
│   ├── types/                  # Shared types
│   └── witness/                # Witness generation
├── circuits/                   # Circom ZK circuits
│   ├── src/
│   │   ├── core/               # Rust circuit helpers (Merkle, ...)
│   │   ├── poseidon2/          # Poseidon2 hash circuits
│   │   ├── smt/                # Sparse Merkle tree circuits
│   │   ├── test/               # Circuit test utilities
│   │   ├── policyTransaction.circom      # Base transact circuit
│   │   ├── aspMembership.circom          # ASP allowlist proof subcircuit
│   │   ├── aspNonMembership.circom       # ASP blocklist proof subcircuit
│   │   ├── policyTransactionOpen.circom  # Open-policy transaction circuit
│   │   ├── policyTransactionAllowlist.circom  # Allowlist-only transaction circuit
│   │   ├── policyTransactionBlocklist.circom  # Blocklist-only transaction circuit
│   │   ├── policyTransactionBoth.circom  # Both-policy transaction circuit
│   │   ├── policy_tx_2_2[_A|_B|_AB].circom  # Entry points
│   │   └── *.circom            # Supporting circuits
│   └── build.rs                # Circuit compilation build script
├── circuit-keys/               # Helpers to convert snarkjs keys to Arkworks
├── contracts/                  # Soroban smart contracts
│   ├── asp-membership/         # ASP membership Merkle tree
│   ├── asp-non-membership/     # ASP non-membership sparse Merkle tree
│   ├── circom-groth16-verifier/# On-chain Groth16 proof verifier
│   ├── pool/                   # Main privacy pool contract
│   ├── public-key-registry/    # On-chain public key registry
│   ├── soroban-utils/          # Shared utilities (Poseidon2, etc.)
│   └── types/                  # Shared contract types
├── poseidon2/                  # Poseidon2 hash implementation
├── tools/                      # Auxiliary tools
│   ├── bootnode/               # HTTPS JSON-RPC getEvents service (excluded from workspace)
│   └── ceremony-cli/           # Groth16 BN254 trusted-setup ceremony CLI (wraps snarkjs)
├── e2e-tests/                  # End-to-end integration tests
├── deployments/                # Deployment scripts, testnet config, legal notices
├── docs/                       # Project documentation (mdBook source)
├── scripts/                    # Helper scripts
├── vendor/                     # Vendored/patched dependencies (cranelift-control)
├── dist/                       # Built static site output (generated)
└── Makefile                    # Build automation
```

## Prerequisites

- [**Rust**](https://www.rust-lang.org/tools/install) 1.92.0 or later (see `rust-toolchain.toml`).
- [**Circom**](https://github.com/iden3/circom) 2.2.2 or later for circuit compilation.
- [**Stellar CLI**](https://github.com/stellar/stellar-cli) for contract deployment.
- [**Node.js**](https://github.com/nodejs/node) for frontend dependencies.
- [**Trunk**](https://github.com/trunk-rs/trunk) for serving the web application.
- [**Cargo Deny**](https://github.com/EmbarkStudios/cargo-deny)
- [**Typos**](https://github.com/crate-ci/typos?tab=readme-ov-file#install)
- [**Cargo Sort**](https://github.com/DevinR528/cargo-sort)
- SQLite development libraries (e.g. for Debian/Ubuntu `sudo apt install libsqlite3-dev`)
- [**wasm-bindgen-cli**](https://crates.io/crates/wasm-bindgen-cli) (provides `wasm-bindgen-test-runner` for `cargo test --target wasm32-unknown-unknown`)
- [**wasm-pack**](https://rustwasm.github.io/wasm-pack/) for WASM bundling

## Building and testing crates

### Patches

`ark-circom` is [patched](https://github.com/NethermindEth/circom-compat/commits/wasm-no-parallel/) 
(`Cargo.toml` is cleaned up from hardcoded `parallel` features) to allow running 
in a single-threaded WASM - we don't want for now to enable multithreaded wasm support as the proving time is acceptable
while wasm multithreading requires COOP/COEP headers and is much stricter to deploy.
Also we delete `ethereum.rs` module to get rid of many irrelevant dependencies.
`vendor/cranelift-control` is patched - the single dependency `arbitrary` is fixed at the same version as in 
the `soroban-sdk` - see https://github.com/NethermindEth/stellar-private-payments/issues/192.

### Running WASM tests

Some crates include unit tests intended to run under `wasm32-unknown-unknown` via `wasm-bindgen-test`.
The workspace is configured to use `wasm-bindgen-test-runner` as the wasm test runner (see `.cargo/config.toml`),
so you need it available on your `PATH` (typically by installing `wasm-bindgen-cli`).

```bash
# Install wasm-bindgen-cli (version must match `wasm-bindgen` in Cargo.lock)
cargo install wasm-bindgen-cli --version 0.2.126 --locked --force

# Example: run wasm tests for the Stellar core crate
cargo test --target wasm32-unknown-unknown -p stellar
```

### Building Circuits
To explicitly build them:

```bash
# Build circuits
cargo build -p circuits
```

The circuit crate also exposes 2 flags:
- **BUILD_TESTS**: Builds the circom test circuits. Most Circom circuits simply define a template. And if you want to use it or test it, you need to instantiate it with some specific parameters.
For efficiency, the compilation of these circuits test is gatekeeped behind this flag. When enabled, if the verifying keys are not in `testdata`, it will generate them. Deployed testnet keys are committed under `deployments/testnet/circuit_keys`.
- **REGEN_KEYS**: Forces the generation of new verification keys, even if they already exist.

Also, for efficiency reasons, some tests are ignored by default. To run them:
```bash
# Test circuits requires the flag to be enabled
BUILD_TESTS=1 cargo test -p circuits -- --ignored
```
### Building Contracts

```bash
# Build all contracts
stellar contract build --manifest-path Cargo.toml --out-dir target/stellar --optimize --package pool
stellar contract build --manifest-path Cargo.toml --out-dir target/stellar --optimize --package asp-membership
stellar contract build --manifest-path Cargo.toml --out-dir target/stellar --optimize --package asp-non-membership
stellar contract build --manifest-path Cargo.toml --out-dir target/stellar --optimize --package circom-groth16-verifier

# Or use the deployment script which builds automatically
./deployments/scripts/deploy.sh --help
```

### Deploying Contracts
You can use the script `deployments/scripts/deploy.sh` to deploy contracts to a Stellar network.

See `./deployments/scripts/deploy.sh --help` for all options.

Each pool has **ASP policy flags** (`none`, `allowlist`, `blocklist`, or `allowlist-blocklist`) fixed at deploy time. The flags select which transact circuit/VK the pool's verifier embeds. A single deployment can include **multiple pools with different policies**; the script deploys one verifier contract per flag combination used and wires the matching verifier into each pool constructor.

Pool specs accept an optional per-pool prefix:

- `none:native:<TOKEN_CONTRACT_ID>`
- `allowlist:contract:<TOKEN_CONTRACT_ID>`
- `blocklist:native:<TOKEN_CONTRACT_ID>`
- `allowlist-blocklist:contract:<TOKEN_CONTRACT_ID>`

Or pass `--policy-flags` as the default when specs omit the prefix.

For testnet blocklist-only pools, pass `--policy-flags blocklist` (or prefix each `--pool` with `blocklist:`) and omit `--vk-file` to use the committed key at `deployments/testnet/circuit_keys/policy_tx_2_2_B_vk.json`.

Mixed-policy example:

```sh
./deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --asp-levels 10 \
  --pool-levels 10 \
  --max-deposit 1000000000 \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet) \
  --pool allowlist-blocklist:classic:EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO:$(stellar contract id asset --asset EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO --network testnet)
```

For testnet purposes
(https://www.circle.com/eurc#how-to-start-using-eurc, you can use https://faucet.circle.com/ to fund your account (but first add an asset and a trustline in your wallet))

```sh
./deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --policy-flags blocklist \
  --asp-levels 10 \
  --pool-levels 10 \
  --max-deposit 1000000000 \
  --pool native:$(stellar contract id asset --asset native --network testnet) \
  --pool classic:EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO:$(stellar contract id asset --asset EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO --network testnet)
```

Allowlist + blocklist pool:

```sh
./deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --policy-flags allowlist-blocklist \
  --asp-levels 10 \
  --pool-levels 10 \
  --max-deposit 1000000000 \
  --pool native:$(stellar contract id asset --asset native --network testnet)
```

### End-to-End Tests

The E2E tests generate real Groth16 proofs and verify them, locally, using contracts and the Soroban-SDK. To run them:
```bash
cargo test -p e2e-tests
```

## Code quality assurance

Install a pre-push git hook:

```sh
git config core.hooksPath .githooks
```

## App development

### Prerequisites

* Node.js
* npm

The web application:

```sh
make install
make serve
```

Production build:

```sh
make release
```

### Browser SDK (`sdk/web`)

Standalone npm package (`stellar-private-payments-sdk-web`). See [`sdk/web/README.md`](sdk/web/README.md).

Requires [**wasm-bindgen-cli**](https://crates.io/crates/wasm-bindgen-cli) (version must match `Cargo.lock`).

```sh
make install
make sdk-web-build
npm run check:artifacts --prefix sdk/web
npm run check:types --prefix sdk/web
```

CI runs these checks in `.github/workflows/wasm-build.yml`.

## CLI development

Build it in a debug mode

```sh
cargo build -p stellar-private-payments-cli
```

If you build it in a release mode, then ensure that proper data directory is configured.

A CLI *prerelease* can be done with 

```sh
git tag v0.1.0-rc.1 # with a proper new version
git push origin v0.1.0-rc.1
```

then you can install it from the Github with

```sh
./scripts/install.sh --pre
```

To make a production release of CLI

```sh
git tag v0.1.0 # with a proper new version
git push origin v0.1.0
```

## JS license policy maintenance

The JS/npm license policy lives in `.github/js-license-policy.json` and is enforced by `.github/workflows/js-license-audit.yml`. The tooling is POSIX sh + jq (`scripts/check-js-licenses.sh`, `scripts/generate-js-attribution.sh`), so jq must be installed locally; GitHub runners provide it.

- **Allowlist updates**: add a new permissive SPDX identifier to `allowlist` when a PR introduces a dependency whose license is not already listed. Keep the list alphabetically sorted. Compound/dual licenses (e.g. `(MIT OR Apache-2.0)`) are matched as one exact string, not evaluated as boolean SPDX expressions — if a dependency reports one, add that literal string to the allowlist (see `(MIT AND BSD-3-Clause)`, used by app's `sha.js`) rather than expecting the scanner to parse it.
- **Exceptions**: if a dependency's license is not on the allowlist (or its `license` field is missing in `package-lock.json`), add an entry to `exceptions` with `approver: PENDING_PR_REVIEW`, a written justification, and the affected package(s). Scope every exception to its lockfile with `target` (e.g. `"target": "circuits/src/circomlib/package-lock.json"` for circom build tooling) so build-tool carve-outs cannot cover the same package in a runtime footprint; omitting `target` applies the exception repo-wide — avoid unless intentional. Exceptions marked `PENDING_PR_REVIEW` must be ratified by a maintainer before merge. Before adding or editing an exception, run `sh scripts/verify-exception-licenses.sh` to confirm the declared license actually matches the npm registry at the package's *locked* version (not `latest` — some packages relicense between majors) — a manual tool, not run in CI.
- **Nightly job**: the `schedule: cron: 0 3 * * *` trigger runs a full-tree scan (`scripts/check-js-licenses.sh`) and uploads `js-license-scan-report.json` as an artifact, catching newly published advisory/license metadata even when no PR changed.
- **Attribution**: `dist/licenses/THIRD-PARTY-{app,sdk-web}.{json,txt}` are generated at build time by `scripts/generate-js-attribution.sh` (called from `deployments/scripts/stage-dist-legal.sh`). Do not edit them by hand.

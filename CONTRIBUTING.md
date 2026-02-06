# Contributor's guide

## Commit signing

Enable [commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

```sh
git config commit.gpgsign true
```

## Project Structure

```
stellar-private-transactions/
├── app/                        # Browser-based frontend application (See app/README.md for more information)
│   ├── crates/                 # Rust WASM modules
│   │   ├── prover/             # Groth16 proof generation
│   │   └── witness/            # Circom witness calculator
│   ├── js/                     # JavaScript frontend code
│   │   ├── state/              # State management (IndexedDB, sync) (see app/ARCHITECTURE.md for more information)
│   │   ├── ui/                 # UI components 
│   │   └── *.js                # Core modules (bridge, wallet, stellar)
│   └── index.html              # Main application entry
├── circuits/                   # Circom ZK circuits
│   ├── src/
│   │   ├── poseidon2/          # Poseidon2 hash circuits
│   │   ├── smt/                # Sparse Merkle tree circuits
│   │   ├── test/               # Circuit test utilities
│   │   ├── compliantTransaction.circom  # Main transaction circuit
│   │   └── *.circom            # Supporting circuits
│   └── build.rs                # Circuit compilation build script
├── contracts/                  # Soroban smart contracts
│   ├── asp-membership/         # ASP membership Merkle tree
│   ├── asp-non-membership/     # ASP non-membership sparse Merkle tree
│   ├── circom-groth16-verifier/# On-chain Groth16 proof verifier
│   ├── pool/                   # Main privacy pool contract
│   ├── soroban-utils/          # Shared utilities (Poseidon2, etc.)
│   └── types/                  # Shared contract types
├── e2e-tests/                  # End-to-end integration tests
├── poseidon2/                  # Poseidon2 hash implementation
├── scripts/                    # Deployment and utility scripts
│   ├── deploy.sh               # Contract deployment script
│   └── deployments.json        # Deployment output
└── Makefile                    # Build automation
```

## Prerequisites

- [**Rust**](https://www.rust-lang.org/tools/install) 1.92.0 or later (see `rust-toolchain.toml`).
- [**Circom**](https://github.com/iden3/circom) 2.2.2 or later for circuit compilation.
- [**Stellar CLI**](https://github.com/stellar/stellar-cli) for contract deployment.
- **Node.js** for frontend dependencies.
- **wasm-pack** for building WASM modules.
- **Trunk** for serving the web application.
* [cargo deny](https://github.com/EmbarkStudios/cargo-deny)
* [typos](https://github.com/crate-ci/typos?tab=readme-ov-file#install)
* [cargo sort](https://github.com/DevinR528/cargo-sort)

## Building and testing crates

### Building Circuits
To explicitly build them:

```bash
# Build circuits
cargo build -p circuits
```

The circuit crate also exposes 2 flags:
- **BUILD_TESTS**: Builds the circom test circuits. Most Circom circuits simply define a template. And if you want to use it or test it, you need to instantiate it with some specific parameters.
For efficiency, the compilation of these circuits test is gatekeeped behind this flag. When enabled, if the verifying keys are not in `scripts/testdata`, it will generate them.
- **REGEN_KEYS**: Forces the generation of new verification keys, even if they already exist. Should not generally be used, as it might cause issues with deployed contracts.

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
./scripts/deploy.sh --help
```

### Deploying Contracts
You can use the script `scripts/deploy.sh` to deploy contracts to a Stellar network.
An example can be found in the _Demo Application_ section..

See `./scripts/deploy.sh --help` for all options.


### End-to-End Tests

The E2E tests generate real Groth16 proofs and verify them, locally, using contracts and the Soroban-SDK. To run them:
```bash
cargo test -p e2e-tests
```

### JavaScript Tests

```bash
cd app
npm test
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
* python3 (for the static server)

The whole app:

```sh
$ make install
$ make serve
```

The Rust part - check compilation

```sh
$ make wasm
```

Prepare a production build (TODO: enable optimizations and minification)

```sh
$ make dist
```
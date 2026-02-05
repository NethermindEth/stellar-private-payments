# Privacy Pool Browser Application

> **Disclaimer**: This is a **Proof of Concept (PoC)** application intended for demonstration and research purposes only. It has not been audited and should not be used with real assets.

Browser-based zero-knowledge proof generation for private Stellar transactions. This application allows users to interact with the privacy pool contracts directly from their browser, with client-side proof generation.

## Features
- Support for deposits, transfers, and withdrawals
- Real-time synchronization with on-chain state
- Freighter wallet integration for Stellar transactions
- Client-side Groth16 proof generation via WebAssembly
- Local state management with IndexedDB
- Note encryption/decryption
- Simulation of ASP providers for testing


## Architecture

### Module Isolation

The application uses two separate WASM modules that communicate through data-only exchange:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser Runtime                              │
│                                                                     │
│  ┌──────────────────────┐         ┌──────────────────────────────┐  │
│  │   Witness Module     │         │      Prover Module           │  │
│  │                      │         │                              │  │
│  │  witness_calculator  │         │  Groth16 proof generation    │  │
│  │  from circom         │         │  Merkle tree operations      │  │
│  │                      │         │  Poseidon2 hashing           │  │
│  └──────────┬───────────┘         └──────────────┬───────────────┘  │
│             │                                    │                  │
│             │         Uint8Array                 │                  │
│             └──────────────────────>─────────────┘                  │
│                    (data only, no code linking)                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

The bridge module (`js/bridge.js`) orchestrates this data exchange without creating a derivative work of either module.

## Directory Structure

```
app/
├── crates/
│   ├── prover/                    # Rust prover module (WASM)
│   │   ├── src/
│   │   │   ├── lib.rs             # WASM entry point
│   │   │   ├── prover.rs          # Groth16 proof generation
│   │   │   ├── crypto.rs          # Poseidon2 hashing
│   │   │   ├── merkle.rs          # Merkle tree operations
│   │   │   ├── sparse_merkle.rs   # Sparse Merkle tree (SMT)
│   │   │   ├── encryption.rs      # Note encryption/decryption
│   │   │   ├── r1cs.rs            # R1CS constraint parser
│   │   │   ├── serialization.rs   # Field element serialization
│   │   │   └── types.rs           # Common types
│   │   └── Cargo.toml
│   │
│   └── witness/                   # Rust witness module (WASM)
│       ├── src/lib.rs             # Witness calculator bindings
│       └── Cargo.toml
│
├── js/
│   ├── state/                     # State management (see ARCHITECTURE.md)
│   │   ├── db.js                  # IndexedDB wrapper
│   │   ├── pool-store.js          # Pool state tracking
│   │   ├── notes-store.js         # User notes (UTXOs)
│   │   ├── asp-membership-store.js    # ASP membership state
│   │   ├── asp-non-membership-fetcher.js  # ASP non-membership
│   │   ├── public-key-store.js    # Public key registry
│   │   ├── note-scanner.js        # Event scanning for notes
│   │   ├── sync-controller.js     # State synchronization
│   │   └── utils.js               # State utilities
│   ├── ui/                        # UI components
│   │   ├── core.js                # Core UI utilities
│   │   ├── navigation.js          # Page navigation
│   │   ├── notes-table.js         # Notes display
│   │   ├── prover-ui.js           # Prover status UI
│   │   ├── sync-ui.js             # Sync status UI
│   │   ├── address-book.js        # Address book management
│   │   ├── contract-reader.js     # Contract state viewer
│   │   ├── templates.js           # HTML templates
│   │   ├── errors.js              # Error handling
│   │   └── transactions/          # Transaction UI
│   │       ├── deposit.js         # Deposit flow
│   │       ├── withdraw.js        # Withdraw flow
│   │       ├── transfer.js        # Transfer flow
│   │       └── transact.js        # Generic transaction
│   ├── bridge.js                  # Witness/Prover coordination
│   ├── prover-client.js           # Prover WASM interface
│   ├── stellar.js                 # Stellar SDK wrapper
│   ├── transaction-builder.js     # Transaction construction
│   ├── wallet.js                  # Freighter wallet integration
│   ├── worker.js                  # Web Worker for proving
│   └── ui.js                      # Main UI entry point
│
├── __tests__/                     # Jest tests
├── css/                           # Stylesheets
├── assets/                        # Static assets
├── index.html                     # Main application
├── admin.html                     # Admin interface
└── TECHNICAL_SPEC.md              # Technical specification
```

## Building

### Prerequisites

- Rust toolchain with `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) for WASM bundling
- [Trunk](https://trunkrs.dev/) for serving the application
- Node.js for JavaScript dependencies and testing

### Build Commands

From the repository root:

```bash
# Install all dependencies
make install

# Build circuits (required the first time)
make circuits-build

# Build WASM modules and serve
make serve
```

This will:
1. Build the witness WASM module
2. Build the prover WASM module (via Trunk)
3. Install npm dependencies
4. Serve the application at `http://localhost:8080`

### Individual Build Steps

```bash
# Build witness WASM module only
make wasm-witness

# Build everything without serving
make build

# Clean build artifacts
make clean
```

## Development

### Running Tests

```bash
# Run JavaScript tests
npm test
```

### Project Configuration

- `Trunk.toml` - Trunk bundler configuration (at repository root)
- `package.json` - npm dependencies and scripts
- `babel.config.cjs` - Babel configuration for Jest
- `jest.config.cjs` - Jest test configuration
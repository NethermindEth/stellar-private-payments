# Privacy Pool Browser Application

Browser-based zero-knowledge proof generation for private Stellar transactions.

### Module Isolation

The two modules communicate exclusively through **data-only exchange**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser Runtime                              │
│                                                                     │
│  ┌──────────────────────┐         ┌──────────────────────────────┐  │
│  │   Witness Module     │         │      Prover Module           │  │
│  │                      │         │                              │  │
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
The bridge module operates on serialized inputs and outputs and can be replaced without modifying either module.

## Directory Structure

```
app/
├── src/                   # Rust prover module (Apache-2.0)
│   ├── lib.rs             # WASM entry point
│   ├── prover.rs          # Groth16 proof generation
│   ├── crypto.rs          # Poseidon2 hashing
│   ├── merkle.rs          # Merkle tree operations
│   ├── sparse_merkle.rs   # Sparse Merkle tree (SMT) with no_std support
│   ├── r1cs.rs            # R1CS constraint parser
│   ├── serialization.rs   # Field element serialization
│   └── types.rs           # Common types
│
├── js/
│   ├── bridge.js          # Coordinates communication between witness + prover modules
│   ├── witness/           # Circom witness calculator
│   │   ├── index.js       # Witness module wrapper
│   │   └── witness_calculator.js  # Witness calculator from Circom
│   ├── prover/            # Compiled WASM output
│   └── ui.js              # UI interactions
│
├── css/                   # Stylesheets
├── assets/                # Static assets
├── index.html             # Main application
└── Cargo.toml             # Rust dependencies
```

## Building

### Prerequisites

- Rust toolchain with `wasm32-unknown-unknown` target
- [Trunk](https://trunkrs.dev/) for WASM bundling
- Node.js (for witness calculator)

### Build Commands

```bash
# Build WASM module and serve automatically
make serve
```
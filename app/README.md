# Privacy Pool Application

> **Disclaimer**: This is a **Proof of Concept (PoC)** application intended for demonstration and research purposes only. It has not been audited and should not be used with real assets.

Zero-knowledge proof generation for private Stellar payments. This application allows users to interact with the privacy pool contracts directly from their browser, with client-side proof generation.

## Features of the web application
- Support for deposits, transfers, and withdrawals
- Real-time synchronization with on-chain state
- Freighter wallet integration for Stellar transactions
- Client-side Groth16 proof generation via WebAssembly
- Local state management with Sqlite
- Note encryption/decryption
- Simulation of ASP providers for testing (`/admin.html`)


## Architecture

see [ARCHITECTURE.md](app/ARCHITECTURE.md)

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
1. Build WASM modules
2. Install npm dependencies
3. Serve the application at `http://localhost:8080`

### Individual Build Steps

```bash
# Build everything without serving
make build

# Clean build artifacts
make clean
```

## Development

### Project Configuration

- `Trunk.toml` - Trunk bundler configuration (at repository root)
- `package.json` - npm dependencies and scripts

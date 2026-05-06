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

see [ARCHITECTURE.md](ARCHITECTURE.md)

## Building

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the prerequisites.

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

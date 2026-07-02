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

See [architecture](architecture.md) in this book, or [`app/ARCHITECTURE.md`](../../app/ARCHITECTURE.md) in the repo.

## Building

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the prerequisites.

### Build Commands

From the repository root:

```bash
# Install all dependencies (app + sdk/web npm, trunk, wasm targets)
make install

# Build browser SDK (WASM, workers, bundled circuits) and serve the app
make serve
```

This will:
1. Build `sdk/web/dist/` via `npm run build` (includes compiled circuits + LGPL source bundle)
2. Stage the SDK into the Trunk output and bundle app JS
3. Serve the application at `http://localhost:8000`

To build circuits only (without the full web stack):

```bash
make circuits-build
```

### Individual Build Steps

```bash
# Browser SDK only (sdk/web/dist/)
make sdk-web-build

# Full static site without serving
make build

# Clean build artifacts
make clean
```

## Development

### Project Configuration

- `Trunk.toml` - Trunk bundler configuration (at repository root)
- `package.json` - npm dependencies and scripts

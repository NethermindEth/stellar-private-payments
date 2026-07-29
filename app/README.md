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
3. Serve the application at `http://localhost:8000`

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

## Diagnostics & Telemetry UI

The web application settings drawer includes a dedicated **Diagnostics & Telemetry** configuration panel.

### Settings and Actions:
- **Log Level**: Dropdown select controlling verbosity (`Info`, `Debug`, `Trace`).
- **Reveal Sensitive Info**: Gated checkbox to reveal Tier-1 values (e.g., amounts, addresses) in logs (forces to `false` in production compiles).
- **Copy Logs**: Copies formatted in-memory ring-buffer logs to the clipboard.
- **Download Logs**: Downloads the diagnostics trace logs as a `.log` file (`spp-diagnostics.log`).

### Enabling Debug Logs (Release-with-logs profile):
To enable telemetry collection and sensitive-reveal features in the web application browser console, serve/build the frontend using the debug-telemetry target:
```bash
# Serve with debug logs enabled
make serve-debug

# Build frontend with debug logs enabled
make build-debug
```

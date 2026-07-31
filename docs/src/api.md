# API Reference

Detailed API documentation generated from source code via `rustdoc`.

## Core

- [circuits](api/circuits/index.html)

## SDK

- [stellar-private-payments](api/stellar_private_payments/index.html)
- [stellar-private-payments-web](api/stellar_private_payments_web/index.html)

## Contracts

- [pool](api/pool/index.html)
- [asp-membership](api/asp_membership/index.html)
- [asp-non-membership](api/asp_non_membership/index.html)
- [circom-groth16-verifier](api/circom_groth16_verifier/index.html)
- [soroban-utils](api/soroban_utils/index.html)
- [contract-types](api/contract_types/index.html)

## Tests

- [e2e-tests](api/e2e_tests/index.html)

## Logging & Telemetry JS API

The browser-based WASM package (`stellar-private-payments-web`) exposes three public telemetry functions:

### 1. `configureTelemetry(config?: TelemetryConfig): void`
Initializes or dynamically updates the active subscriber's logging filter, target sinks, and diagnostic buffers.
* **Signature**:
  ```typescript
  export function configureTelemetry(config?: {
    level?: string;
    sink?: 'console' | 'ringBuffer' | 'both';
    ringBufferBytes?: number;
    revealSensitive?: boolean;
  }): void;
  ```
* **Configuration Knobs**:
  - `level`: Log filter directive (e.g. `"info"`, `"debug"`, `"trace"`).
  - `sink`: Where logs are directed (`"console"`, `"ringBuffer"`, or `"both"`).
  - `ringBufferBytes`: Capacity of the in-memory diagnostic ring buffer.
  - `revealSensitive`: Gated by profile (`cfg(debug_assertions)`). Set to `true` to reveal Tier-1 values.

### 2. `set_log_level(level: string): void`
Dynamically overrides the active log level filter directive at runtime (e.g., changes to `"debug"`).

### 3. `dump_recent_logs(): Promise<string>`
Dumps the recent formatted logs as a single string for diagnostic reports, aggregated from the main thread and the storage/prover worker isolates (one section per isolate).

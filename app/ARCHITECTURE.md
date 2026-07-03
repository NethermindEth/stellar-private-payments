# App Architecture

This document describes how the application manages local state, including persistent storage and on-chain data.

## Overview

**Core vs browser SDK vs app**

| Layer | Location | Role |
|-------|----------|------|
| **Pool SDK** | `sdk/pool` | Rust `PrivatePool` — deposits, transfers, withdrawals, transact, disclose |
| **Web SDK** | `sdk/web` | npm package `stellar-private-payments-sdk-web` — WASM bindings, workers, `Storage` / `Client` / `PrivatePool` JS API |
| **App** | `app/js` | UI, Freighter connect UX, `wasm-facade.js` lifecycle, `app-storage.js` for app-only persistence |

Core application logic lives in Rust `sdk/` crates (sync primitives, indexer, tx builders, proving, SQLite schema). The browser SDK (`sdk/web`) compiles that logic to WASM and exposes a typed JavaScript API. The `app/` directory is the web UI and a thin runtime facade — it does not embed its own WASM crate.

**Storage**

Local storage is SQLite (`sdk/state/src/storage.rs`, schema in `sdk/state/src/schema.sql`), shared across platforms. In the browser the database file (`poolstellar.sqlite`) lives on OPFS behind the storage worker.

## Browser SDK (`sdk/web`)

The web SDK runs Rust on the main thread via WASM, with blocking work offloaded to Web Workers. It is built with `npm run build` in `sdk/web` and consumed by the app as a local npm dependency (`app/package.json` → `file:../sdk/web`).

### Lifecycle

```
init() → Storage.open() → Client.new() → checkSync() → startSync() → initialize(signer) → client.pool() → PrivatePool ops
```

The app wraps this in `wasm-facade.js` and `ui/pool.js`: `initializeRuntime` → `client().startSync` → `client().initializeWallet` → `createAppPool()` / `ensureAppPool()`.

### Components

The WASM layer exposes three JS handles with different scope:

| Handle | Scope | Examples |
|--------|-------|----------|
| **`Storage`** | Page-local persistence (one worker per tab) | `open`, `fork`, `call` (raw worker RPC) |
| **`Client`** | Account + deployment (all pools) | `contractConfig`, `allContractsData`, `registerPublicKeys`, `pool()` |
| **`PrivatePool`** | One pool contract + user session | `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `sync`, `getBalance` |

`Client` is the long-lived session shell; `PrivatePool` is created per active pool when the user transacts.

**JS UI (main thread)**

The UI is JavaScript. It imports the SDK package (or `wasm-facade.js` helpers) and does not talk to workers directly.

**Main thread (WASM)**

- Entry: `init()` from `stellar-private-payments-sdk-web` (wasm-bindgen module init).
- `Client::new` forks a `Storage` handle and holds RPC URL; wallet binding happens at `initialize`.
- `events::start_indexer` spawns the background contract-event loop (`events_listener`).

**Indexer (pool SDK + web SDK)**

- Generic over a storage backend (`Indexer<S: ContractDataStorage>`).
- On web, the backend is **`StorageBridge`**, implementing `ContractDataStorage` and the pool SDK `Storage` trait by forwarding to the storage worker.
- `events_listener` (`sdk/web/src/events.rs`) owns the long-running loop: `Indexer::init`, periodic `fetch_contract_events`, bootnode handoff when the wallet RPC has a retention gap.
- Background sync is owned by the indexer, not by the UI calling `pool.sync()` on every page load (though pool ops call `sync` before/after mutations for freshness).

**`Storage` (WASM, wasm-bindgen API)**

- Spawns the storage worker once per page (`Storage.open({ workerUrl? })`).
- `fork()` returns another handle to the same worker/DB (used internally by `Client::new`).
- `call(request, timeoutMs?)` exposes the typed worker protocol for advanced/app-layer use.

**`Client` (WASM, wasm-bindgen API)**

- Constructed by `Client.new({ storage, rpcUrl })` — shell only, no wallet yet.
- Spawns the prover worker at `initialize`; routes storage requests through `StorageBridge`.
- **Account- and deployment-wide operations:**
  - Wallet bind + key derivation at `initialize` (Freighter `signMessage` when keys missing in local DB).
  - Chain reads: `contractConfig`, `allContractsData`, `lookupRegisteredPublicKey`, `registerPublicKeys`.
  - Selective-disclosure verification without a wallet session (`verifySelectiveDisclosure`).
  - Per-pool sessions via `pool({ poolContract })`.

**`PrivatePool` (WASM, wasm-bindgen API)**

- Per-pool session: pool SDK `PrivatePool<StorageBridge>` with RPC fetcher, shared storage bridge, prover bridge, and wallet signer.
- **Pool-scoped operations** — the app caches the handle in `ui/pool.js` (`activeSession` via `createAppPool` / `ensureAppPool` / `closeAppPool`) until wallet disconnect or pool switch.
- Exports: `sync`, `getBalance`, `notes`, `estimate`, `deposit`, `transfer`, `transferToKeys`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`.
- Amounts are **stroops** as JavaScript `bigint` (same units as Rust `NoteAmount`).
- Proving, signing, and submit run inside this session; returns tx hashes to JS.

**`StorageBridge` (WASM main thread)**

- Typed async bridge to the storage worker (`StorageWorkerRequest` / `StorageWorkerResponse` in `protocol.rs`).
- Used by the indexer, `PrivatePool`, and `ClientCore` storage reads.

**Storage worker (Web Worker)**

- Owns SQLite on OPFS.
- Saves raw contract events, processes events, scans/decrypts notes, maintains derived state.
- Processes in small chunks and yields between batches to stay responsive.

**Prover worker (Web Worker)**

- Long-running Groth16 proving and witness calculation.
- Does not persist user state; caches circuit artifacts in memory.

### Worker protocol

The `sdk/web` crate owns worker spawning and communication. Messages are strongly typed enums in `protocol.rs` (`StorageWorkerRequest/Response`, `ProverWorkerRequest/Response`). The protocol is not part of the public JS API except via `Storage.call` for app-layer extensions.

### Data flow

```mermaid
flowchart LR
  subgraph JS["JS UI (main thread)"]
    UI["UI + wasm-facade.js"]
    AS["AppStorage (settings, disclaimer, op history)"]
  end

  subgraph PKG["stellar-private-payments-sdk-web"]
    ST["Storage"]
    CL["Client"]
    PP["PrivatePool"]
    SB["StorageBridge"]
    EL["events_listener"]
    IDX["Indexer"]
  end

  subgraph SW["Storage worker"]
    DB["SQLite (OPFS)"]
  end

  subgraph PW["Prover worker"]
    PR["Prover + witness"]
  end

  subgraph RPC["Stellar RPC"]
    RPCAPI["State + events"]
  end

  UI --> ST
  UI --> CL
  UI --> PP
  AS -->|"Storage.call"| ST
  CL --> ST
  CL --> SB
  CL -->|"pool()"| PP
  PP --> SB
  PP --> PW
  EL --> IDX
  IDX --> RPCAPI
  IDX --> SB
  SB --> SW
  PW --> PR
  CL --> RPCAPI
  PP --> RPCAPI
```

## App runtime (`app/js`)

**`wasm-facade.js`**

Single entry for the main app pages. Owns singleton lifecycle:

1. `initializeRuntime(rpcUrl)` — `init()`, `Storage.open`, `Client.new`
2. `client().startSync({ bootnodeUrl? })` — `checkSync` when bootnode omitted, then background indexer
3. `client().initializeWallet({ networkPassphrase, userAddress }, signer)` — `Client.initialize`
4. `createAppPool()` / `ensureAppPool()` in `ui/pool.js` — `client().pool({ poolContract })`

Also wraps the SDK `Client` with storage-backed helpers still migrating to the SDK (`getUserNotes`, `getPortfolioBalances`, `loadPublicKeys`, `aspState`, etc.) via `Storage.call`.

**`app-storage.js`**

App-only persistence on top of `Storage.call`: explorer settings, bootnode config, disclaimer acceptance, operation history. Not part of the published SDK.

**`app/js/wallet.js`**

Freighter connect/watch/sign UX for the app UI. Distinct from `sdk/web/js/freighter.js` (`FreighterSigner`), which implements the SDK `WalletSigner` interface passed to `Client.initialize`.

**Build (Trunk)**

`Trunk.toml` stages `sdk/web/dist/` (WASM, workers, **bundled circuits** under `dist/circuits/`) and bundles `sdk/web/js/index.js` into `js/stellar-private-payments-sdk-web/`. App bundles (`ui.js`, etc.) import `stellar-private-payments-sdk-web` as an external package via import maps in `index.html`.

Root-level `circuits/` in the deployed site holds **legal files only** (`NOTICE.txt`, `source-bundle.tar.gz` for footer links). Proving loads artifacts from the SDK copy via the prover worker loader (`__STELLAR_PRIVATE_PAYMENTS_CIRCUITS_BASE__`).

## Keypair derivation

Keys are derived deterministically from Freighter wallet signatures:

1. User signs `KEY_DERIVATION_MESSAGE` from `sdk/prover/src/encryption.rs` (`"Privacy Pool Key Derivation [v1]"`).
2. The worker derives the BN254 note identity keypair and the X25519 encryption keypair from that signature using domain-separated hashes.
3. Derived keys are stored in SQLite; the signature is not persisted.

Signatures are prompted during onboarding so the app can scan for notes addressed to the user.

## Public key registry

Registered note + encryption public keys on-chain enable private transfers to `G...` addresses. `Client.lookupRegisteredPublicKey` / `PrivatePool.transfer` resolve recipients through the local registry index (backed by synced contract events).

## Recovery scenarios

### Clearing browser data

All local data is lost. On next load:

1. Full sync from RPC (limited by RPC retention, typically [~7 days](https://developers.stellar.org/docs/data/apis/rpc)).
2. Merkle trees rebuilt from synced events.
3. User must re-sign for key derivation.
4. Note scanning rediscovers received notes.
5. Events older than the retention window cannot be recovered without a bootnode.

### Account switch

Freighter account change triggers disconnect. The user reconnects and re-runs onboarding if keys for the new account are not in local storage. Background indexing uses the connected account's derived keys for decryption.

### RPC sync gap

When the wallet RPC cannot serve the full event history, `checkSync` / `startSync` surface `RPC_SYNC_GAP`. The app prompts for a bootnode URL, persists it in app settings, and the indexer catches up via bootnode before handing off to the wallet RPC.

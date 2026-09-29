# App Architecture

This document describes how the application manages local state, including persistent storage and on-chain data.

## Overview

**Core vs browser SDK vs app**

| Layer | Location | Role |
|-------|----------|------|
| **Rust SDK** | `sdk/native` | Rust `PrivatePool` — deposits, transfers, withdrawals, transact, disclose |
| **Web SDK** | `sdk/web` | npm package `stellar-private-payments` — WASM bindings, workers, `Storage` / `Client` / `PrivatePool` JS API |
| **App** | `app/js` | UI, Freighter connect UX, `wasm-facade.js` lifecycle, `app-storage.js` for app-only persistence |

Core application logic lives in Rust `sdk/` crates (sync primitives, indexer, tx builders, proving, SQLite schema). The browser SDK (`sdk/web`) compiles that logic to WASM and exposes a typed JavaScript API. The `app/` directory is the web UI and a thin runtime facade — it does not embed its own WASM crate.

**Storage**

Local storage is SQLite (`sdk/native/src/state/storage.rs`, schema in `sdk/native/src/state/schema.sql`), shared across platforms. In the browser, the storage worker opens a plaintext public chain cache (`spp.public.db`) and keeps the private vault (`spp.encrypted.db`) locked until requested. The vault is encrypted with SQLite3 Multiple Ciphers and retains chain rows referenced by private notes; the cache contains only public chain data and explorer/bootnode settings. Its random key is sealed with the user's password (Argon2id) in `spp.key.db` next to it and unsealed inside the worker, so the page never holds the key. The first password encrypts an unencrypted `spp.db` left by earlier versions, then deletes it.

## Browser SDK (`sdk/web`)

The web SDK runs Rust on the main thread via WASM, with blocking work offloaded to Web Workers. It is built with `npm run build` in `sdk/web` and consumed by the app as a local npm dependency (`app/package.json` → `file:../sdk/web`).

### Lifecycle

```
init() → Storage.connect() → bootnodeRequired() → Client.new() → backgroundSync()
private access → status() → create(password) | unlock(password) → client.account(options, signer) → account.pool() → PrivatePool ops
```

The app wraps this in `wasm-facade.js` and `ui/pool.js`: `bootnodeRequired` → `initializeRuntime` → `client().backgroundSync` → `client().openAccount` → `account().pool()` via `createAppPool()` / `ensureAppPool()`.

### Components

The WASM layer exposes four JS handles with different scope:

| Handle | Scope | Examples |
|--------|-------|----------|
| **`Storage`** | Page-local persistence (one worker per tab) | `open`, `fork`, `call` (app-layer settings only) |
| **`Client`** | Deployment runtime (storage, RPC, sync) | `contractConfig`, `backgroundSync`, `operationalFeed`, `recipientLookup`, `account()` |
| **`Account`** | Wallet session (address + signer) | `portfolio`, `privacyKeys`, `aspSecret`, `userNotes`, `isRegistered`, `deriveAspUserLeaf`, `registerPublicKeys`, `pool()` |
| **`PrivatePool`** | One pool contract + user session | `deposit`, `transfer`, `withdraw`, `transact`, `disclose`, `balance`, `notes` |

`Client` is the long-lived deployment shell; `Account` is created when the wallet binds; `PrivatePool` is created per active pool when the user transacts. Free helpers such as `deriveAspUserLeaf(notePublicKey, membershipBlinding)` need neither wallet nor storage.

**JS UI (main thread)**

The UI is JavaScript. It imports the SDK package (or `wasm-facade.js` helpers) and does not talk to workers directly.

**Main thread (WASM)**

- Entry: `init()` from `stellar-private-payments` (wasm-bindgen module init).
- `Client::new` forks a `Storage` handle and holds RPC URL + optional bootnode; wallet binding happens at `account`.
- `Client::backgroundSync` spawns the native SDK `BackgroundSync` loop (`wasm_bindgen_futures::spawn_local`).

**Indexer (client SDK + web SDK)**

- Generic over a storage backend (`Indexer<S: ContractDataStorage>`).
- On web, the backend is **`StorageBridge`**, implementing `ContractDataStorage` and the client SDK `Storage` trait by forwarding to the storage worker.
- `BackgroundSync::run` (`sdk/native/src/sync.rs`) owns the long-running loop: `Indexer::init`, periodic `fetch_contract_events`, bootnode handoff when the wallet RPC has a retention gap. `bootnodeRequired` (native `bootnode_required`, wasm in `sdk/web/src/bootnode.rs`) is a one-shot probe only.
- Background sync is owned by that loop. Pool sessions do not expose `sync()`; use `client.sync()` for an explicit catch-up when needed.

**`Storage` (WASM, wasm-bindgen API)**

- Spawns the storage worker once per page (`Storage.connect({ workerUrl? })`); the public cache opens immediately; the private vault stays closed until `create(password)` or `unlock(password)`, as `status()` asks.
- `changePassword(current, next)` re-seals the key; `reset()` deletes the local database for a forgotten password; `close()` releases it.
- `fork()` returns another handle to the same worker/DB (used internally by `Client::new`).
- `call(request, timeoutMs?)` exposes the typed worker protocol for advanced/app-layer use.

**`Client` (WASM, wasm-bindgen API)**

- Constructed by `Client.new({ rpcUrl, storage, proverWorkerUrl?, bootnodeUrl? })` — wraps native SDK `Client` plus worker bridges; no wallet yet.
- Spawns the prover worker at `Client.new`. Routes storage through `StorageBridge`.
- **Deployment-wide operations:**
  - Background sync via `backgroundSync`.
  - Chain reads without a wallet: `contractConfig`, `operationalFeed`, `recipientLookup`, `allContractsData`, `aspState`, `verifySelectiveDisclosure`.
  - Account factory via `account({ networkPassphrase, userAddress?, signerAddress? }, signer)`.

**`Account` (WASM, wasm-bindgen API)**

- Wallet session: thin wrapper over native `Account`.
- **Account-wide operations:**
  - `derivePrivacyKeys()` — explicit call, Freighter `signMessage` when keys missing in local DB; the signature is verified against the note owner before keys are derived or saved.
  - Reads: `portfolio`, `privacyKeys`, `aspSecret`, `userNotes`, `isRegistered`, `deriveAspUserLeaf`.
  - `registerPublicKeys`.
  - Per-pool sessions via `pool({ poolContract })`.

**`PrivatePool` (WASM, wasm-bindgen API)**

- Per-pool session: client SDK `PrivatePool<StorageBridge>` with RPC fetcher, shared storage bridge, prover bridge, and wallet signer.
- **Pool-scoped operations** — the app caches the handle in `ui/pool.js` (`activeSession` via `createAppPool` / `ensureAppPool` / `closeAppPool`) until wallet disconnect or pool switch.
- Exports: `balance`, `notes`, `estimate`, `deposit`, `transfer`, `transferToKeys`, `withdraw`, `transact`, `disclose`, `verifyDisclosure`.
- Amounts are **stroops** as JavaScript `bigint` (same units as Rust `NoteAmount`).
- Proving, signing, and submit run inside this session; returns tx hashes to JS.

**`StorageBridge` (WASM main thread)**

- Typed async bridge to the storage worker (`StorageWorkerRequest` / `StorageWorkerResponse` in `protocol.rs`).
- Used by the indexer, `PrivatePool`, and wasm `Client` storage reads.

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

  subgraph PKG["stellar-private-payments"]
    ST["Storage"]
    CL["Client"]
    AC["Account"]
    PP["PrivatePool"]
    SB["StorageBridge"]
    BS["BackgroundSync"]
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
  UI --> AC
  UI --> PP
  AS -->|"Storage.call"| ST
  CL --> ST
  CL --> SB
  CL -->|"account()"| AC
  CL -->|"backgroundSync()"| BS
  AC -->|"pool()"| PP
  PP --> SB
  PP --> PW
  BS --> IDX
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

1. `bootnodeRequired(rpcUrl)` — probe retention; configure/persist bootnode if needed
2. `initializeRuntime(rpcUrl)` — `init()`, `Storage.connect` for public persistence, `Client.new` (loads stored bootnode). `ensurePrivateStorage()` opens the password dialog only when private data is requested
3. `client().backgroundSync()` — spawn indexer; public onboarding runs without reading private preferences. Its explicit private-setup action calls `ensurePrivateStorage()` before continuing with disclaimer acceptance and key derivation
4. `client().openAccount({ networkPassphrase, userAddress }, signer)` — `Client.account`
5. `createAppPool()` / `ensureAppPool()` in `ui/pool.js` — `account().pool({ poolContract })`

Also wraps the SDK `Client` for app lifecycle (`openAccount`, cached account session). Privacy key reads use SDK methods; app-only persistence (disclaimer, explorer, bootnode, operation history) stays on `client().storage()` via `Storage.call`.

**`app-storage.js`**

App-only persistence on top of `Storage.call`: explorer settings, bootnode config, disclaimer acceptance, operation history. Not part of the published SDK.

**`app/js/wallet.js`**

Freighter connect/watch/sign UX for the app UI. Distinct from `sdk/web/js/freighter.js` (`FreighterSigner`), which implements the SDK `WalletSigner` interface passed to `Client.account`. Both adapters intentionally use the SEP-0043 standardized sign/get methods where they exist; the remaining Freighter-only connect/permission and watch calls are isolated at this adapter boundary because SEP-0043 (Draft) does not yet define replacements. The network-URL call (`getNetworkDetails` for `sorobanRpcUrl`) is a separate, permanent exception rather than a Draft gap: SEP-0043's `getNetwork` has no RPC-URL field at all, standard or Draft, so there is no SEP path to migrate to.

**Build (Trunk)**

`Trunk.toml` stages `sdk/web/dist/` (WASM, workers, **bundled circuits** under `dist/circuits/`) and bundles `sdk/web/js/index.js` plus the opt-in `sdk/web/js/freighter.js` into `js/stellar-private-payments/`. App bundles (`ui.js`, etc.) import `stellar-private-payments` / `stellar-private-payments/freighter` as external packages via import maps in `index.html`.

Root-level `circuits/` in the deployed site holds **legal files only** (`NOTICE.txt`, `source-bundle.tar.gz` for footer links). Proving loads artifacts from the SDK copy via the prover worker loader (`__STELLAR_PRIVATE_PAYMENTS_CIRCUITS_BASE__`).

## Keypair derivation

Keys are derived deterministically from Freighter wallet signatures:

1. The app calls `account.derivePrivacyKeys()` explicitly (during onboarding); the wallet signs `KEY_DERIVATION_MESSAGE` from `sdk/native/src/zk/encryption.rs` (`"Privacy Pool Key Derivation [v1]"`) using SEP-53.
2. `Account::derive_privacy_keys` calls `verify_owner_signature` to strictly verify the 64-byte Ed25519 signature against the note owner's Stellar `G...` public key before trusting it. The signed digest is `SHA256("Stellar Signed Message:\n" + message)`, using UTF-8 bytes and a newline after the colon. Verification refuses signatures from another key, signatures over another message, invalid lengths or addresses, and small-order owner keys or signature `R` points.
3. It then derives the BN254 note identity keypair and the X25519 encryption keypair from the verified signature using domain-separated hashes, plus the ASP membership blinding using the network context (main thread on web, not inside the storage worker).
4. Derived keys are sent to storage and persisted in SQLite; the signature is not persisted. Verification failure stops derivation before any privacy keys are derived or saved.

Signatures are prompted during onboarding so the app can scan for notes addressed to the user. The derivation algorithm is unchanged. Existing stored keys skip message signing and verification; this check does not retroactively validate them.

The requested transaction signer must match the note owner when keys are missing. This address check avoids an unnecessary wallet prompt, while signature verification catches a wallet signing with another key even if its reply omits or misreports the signer address. Once the owner's keys are stored, a session may use a different transaction signer without a new derivation signature. CLI onboarding uses the same verification helper before creating missing keys.

## Public key registry

Registered note + encryption public keys on-chain enable private transfers to `G...` addresses. `Client.recipientLookup` / `PrivatePool.transfer` resolve recipients through the local registry index (backed by synced contract events).

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

When the wallet RPC cannot serve the full event history, `bootnodeRequired` returns true. The app prompts for a bootnode URL, persists it in app settings, and the indexer catches up via bootnode before handing off to the wallet RPC.

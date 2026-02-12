# App Architecture: Local State Management

This document describes how the web application manages local state, including persistent storage, in-memory caches, and their relationships to on-chain data.

## Overview

The app uses a layered state management architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                      StateManager (index.js)                    │
│                  Unified API for all state operations           │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────┤
│  PoolStore  │ ASPMember-  │ NotesStore  │ PublicKey-  │ Sync-   │
│             │ shipStore   │             │ Store       │ Control │
├─────────────┴─────────────┴─────────────┴─────────────┴─────────┤
│                      IndexedDB (db.js)                          │
│                    Persistent Browser Storage                   │
└─────────────────────────────────────────────────────────────────┘
```
Please note that the ASP Non-membership it is not part of the architecture.
This is because in the current implementation, the SMT is stored directly on-chain and we can simply query the contract.

## Storage Layer

### IndexedDB (`db.js`)

All persistent data is stored in IndexedDB under the database name `poolstellar`. The schema includes:

| Store Name | Key | Purpose | Indexes |
|------------|-----|---------|---------|
| `retention_config` | `rpcEndpoint` | Caches RPC retention window detection | - |
| `sync_metadata` | `network` | Tracks sync progress (cursors, last ledger) | - |
| `pool_leaves` | `index` | Pool merkle tree leaves (commitments) | `by_commitment` |
| `pool_nullifiers` | `nullifier` | Spent note nullifiers | - |
| `pool_encrypted_outputs` | `commitment` | Encrypted note data for scanning | `by_ledger` |
| `asp_membership_leaves` | `index` | ASP membership tree leaves | `by_leaf` |
| `user_notes` | `id` (commitment) | User's discovered/created notes | `by_spent`, `by_owner` |
| `registered_public_keys` | `address` | Address book of public keys | `by_ledger` |

## Domain Stores

### Pool Store (`pool-store.js`)

Manages the privacy pool's state including commitments, nullifiers, and encrypted outputs.

**Persistent Data (IndexedDB):**
- `pool_leaves`: Leaf commitments forming the private pool Merkle tree.
- `pool_nullifiers`: Nullifier hashes marking spent notes.
- `pool_encrypted_outputs`: Encrypted note data for recipient scanning.

**In-Memory Cache:**
- `merkleTree`: Live merkle tree instance on user-side.
  - Initialized from `pool_leaves` on startup via cursor iteration.
  - Updated incrementally as new commitments are synced.
  - Used for generating Merkle proofs for ZK circuits.

The Merkle tree cache is critical for transaction building.
Without it, users cannot generate proofs.
We must make sure it is synced with the on-chain contract. 

### ASP Membership Store (`asp-membership-store.js`)

Manages the Association Set Provider (ASP) membership tree for membership and non-membership policy proofs.

**Persistent Data (IndexedDB):**
- `asp_membership_leaves`: Sequential membership leaves with their roots

**In-Memory Cache:**
- `merkleTree`: Live ASP membership tree instance
  - Same initialization pattern as pool store
  - Verifies roots match on-chain state during sync

As it happens with `pool-store.js` Merkle tree. It must be up to date for proofs to work.

### ASP Non-Membership Fetcher (`asp-non-membership-fetcher.js`)

Unlike other stores, this module fetches proofs on-demand from the contract rather than syncing locally.

**No Persistent State** - Queries the contract's `find_key` function via `simulateTransaction`.

Non-membership proofs are not cached. Each transaction requiring a non-membership proof makes an RPC call.

### Notes Store (`notes-store.js`)

Manages user notes and cryptographic keypair derivation.

**Persistent Data (IndexedDB):**
- `user_notes`: User's notes with amount, blinding, leaf index, spent status.

**In-Memory State:**
- `cachedEncryptionKeypair`: X25519 keypair (populated after transactions, used by note scanning)
- `cachedNoteKeypair`: BN254 keypair (populated after transactions, used by note scanning)
- `currentOwner`: Active Stellar address for note filtering

**Keypair Derivation:**
Keys are derived deterministically from Freighter wallet signatures:
1. User signs message `"Privacy Pool Spending Key [v1]"` → derives BN254 note identity keypair
2. User signs message `"Sign to access Privacy Pool [v1]"` → derives X25519 encryption keypair

**When are signatures prompted?**
- **Transactions (deposit/withdraw/transfer):** Always prompt for both signatures. Keys are re-derived each time as a security measure ensuring user presence and consent.
- **Note scanning during sync:** Uses the in-memory cache if available. After a transaction derives keys, they're cached so the subsequent sync can scan for notes without additional prompts.

The keypair cache only benefits the sync/note-scanning flow. Transactions intentionally re-derive keys each time. Cache is cleared on logout, account switch, or page refresh.

### Public Key Store (`public-key-store.js`)

Maintains an address book of registered public keys in the pool contract for sending private transfers.

**Persistent Data (IndexedDB):**
- `registered_public_keys`: Address → (encryptionKey, noteKey, ledger)

Enables finding recipient keys without on-chain queries.
Falls back to on-chain search if not found locally.

### Note Scanner (`note-scanner.js`)

Discovers notes addressed to the user by scanning encrypted outputs.

**In-Memory State:**
- `lastScannedLedger`: Tracks scan progress to avoid re-scanning

**Scanning Process:**
1. Fetches encrypted outputs from pool store (optionally from a specific ledger)
2. Attempts decryption using user's X25519 encryption private key
3. Verifies commitment matches using note public key
4. Saves discovered notes addressed to the user into notes store

The `lastScannedLedger` prevents redundant decryption attempts but is lost on page reload, triggering a full rescan.

### Sync Controller (`sync-controller.js`)

Orchestrates blockchain synchronization for all stores.

**Persistent Data (IndexedDB):**
- `sync_metadata`: Per-network tracking of:
  - `poolSync.lastLedger`, `poolSync.lastCursor`
  - `aspMembershipSync.lastLedger`, `aspMembershipSync.lastCursor`
  - `syncBroken` flags for gap detection

**In-Memory State:**
- `isSyncing`: Prevents concurrent sync operations
- Event listeners for progress reporting

**Sync Flow:**
```
1. Check retention window (RPC can configure their event history, usually 7d)
2. Detect sync gap (compare lastSyncedLedger vs latestLedger)
3. If gap > retention window → mark sync as broken
4. Fetch Pool events → process commitments, nullifiers, public keys
5. Fetch ASP Membership events → process leaf additions
6. Optionally scan for notes and check spent status
7. Update sync metadata with new cursors
```

Cursors enable incremental sync.
If sync is broken (offline too long), historical events cannot be recovered from RPC.
This is a limitation already addressed in the root level `README.md`.

### Retention Verifier (`retention-verifier.js`)

Detects and caches the RPC's event retention window.

**Persistent Data (IndexedDB):**
- `retention_config`: Cached detection result per RPC endpoint

**Detection Logic:**
1. Try fetching events from 7 days ago.
2. If fails, try 24 hours ago.

Determines the warning threshold for sync gaps.
Users are warned when approaching the retention limit to prevent data loss.

## Cache Relationships

```
┌──────────────────────────────────────────────────────────────────────┐
│                          On-Chain State                              │
│    Pool Contract       ASP Membership       ASP Non-Membership       │
└──────────┬──────────────────┬───────────────────────┬────────────────┘
           │ Events           │ Events                │ Direct Query
           ▼                  ▼                       ▼
┌────────────────────────────────────────┐  ┌──────────────────────────┐
│            Sync Controller             │  │ ASP Non-Membership       │
│  - Fetches events from both contracts  │  │ Fetcher (no local state) │
│  - Tracks cursors per contract         │  └──────────────────────────┘
└──────────┬──────────────────┬──────────┘
           │                  │
           ▼                  ▼
┌───────────────────┐  ┌───────────────────┐
│    Pool Store     │  │ ASP Membership    │
│  - IndexedDB      │  │ Store             │
│  - Merkle Tree    │  │  - IndexedDB      │
│    (in-memory)    │  │  - Merkle Tree    │
└─────────┬─────────┘  │    (in-memory)    │
          │            └───────────────────┘
          ▼
┌───────────────────┐     ┌───────────────────┐
│   Note Scanner    │────▶│    Notes Store    │
│  - Scan progress  │     │  - IndexedDB      │
│    (in-memory)    │     │  - Keypairs       │
└───────────────────┘     │    (in-memory)    │
                          └───────────────────┘
```

## Data Flow Examples

### Creating a Deposit

1. User enters amount.
2. App derives note keypair (from cache or Freighter signature).
3. Transaction builder creates commitment using Poseidon2.
4. Transaction submitted to Pool contract.
5. Sync picks up `NewCommitmentEvent`.
6. Pool store adds leaf to IndexedDB and Merkle tree.
7. Notes store saves note.

### Receiving a Transfer

1. Sync fetches `NewCommitmentEvent` with encrypted output.
2. Pool store saves encrypted output to IndexedDB.
3. Note scanner attempts decryption with user's X25519 key.
4. If successful, verifies commitment with note public key.
5. Saves note to notes store (marked as `isReceived: true`).

### Spending a Note

1. User selects notes to spend.
2. App fetches Merkle proof from pool store's in-memory tree.
3. App fetches ASP membership proof from ASP membership store.
4. ZK proof generated with note private key.
5. Transaction submitted with nullifier.
6. Sync picks up `NewNullifierEvent`.
7. Pool store records nullifier.
8. Note scanner marks note as spent.

## Recovery Scenarios

### Clearing Browser Data

All IndexedDB data is lost. On next load:
1. Full sync from RPC (limited by retention window).
2. Merkle trees rebuilt from synced events.
3. User must re-authenticate for keypair derivation.
4. Note scanning rediscovers received notes.
5. If events are older than retention window, they cannot be recovered.

### Account Switch

1. `clearKeypairCaches()` called.
2. `setCurrentOwner()` updated.
3. Notes filtered to new owner.
4. User must re-authenticate (sign wallet messages) for note operations.


## File Reference

| File | Responsibility |
|------|----------------|
| `state/index.js` | StateManager facade, event forwarding |
| `state/db.js` | IndexedDB wrapper, schema definition |
| `state/pool-store.js` | Pool commitments, nullifiers, merkle tree |
| `state/asp-membership-store.js` | ASP membership tree |
| `state/asp-non-membership-fetcher.js` | On-demand non-membership proofs |
| `state/notes-store.js` | User notes, keypair management |
| `state/public-key-store.js` | Address book |
| `state/note-scanner.js` | Encrypted output scanning |
| `state/sync-controller.js` | Event synchronization orchestration |
| `state/retention-verifier.js` | RPC retention window detection |
| `state/utils.js` | Hex/bytes conversion, tree utilities |

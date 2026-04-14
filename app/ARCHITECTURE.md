# App Architecture

This document describes how the application manages local state, including persistent storage and on-chain data.

## Overview

**Core vs platforms**

Core application logic is implemented in Rust `app/crates/core` crates which define sync and async primitives and building blocks.
Platforms `app/crates/platforms` (`web`, in the future - `cli`, `mcp` etc) provide compilation target specific dependencies, setup runtime (asynchronous/threaded), ui interaction protocol (e.g. FFI/http), order of operations.

Other directories in `app` directory mostly define interfaces for the `web` platform but probably can be restructred in the future to include other platforms interfaces as well.

**Storage:**

Local storage is implemented upon SQLite (`app/crates/core/state/src/storage.rs`) with the schema `app/crates/core/state/src/schema.sql` to have a unified storage accross different platforms allowing future syncs across platforms.

**Keypair Derivation:**

Keys are derived deterministically from Freighter wallet signatures:
1. User signs message defined by the constant `SPENDING_KEY_MESSAGE` from `app/crates/core/prover/src/encryption.rs` → derives BN254 note identity keypair
2. User signs message defined by the constant `ENCRYPTION_MESSAGE` from `app/crates/core/prover/src/encryption.rs` → derives X25519 encryption keypair

**When are signatures prompted?**

At the user onboarding to allow to scan for notes addressed to the user. The derived keys are stored permanently.

### Public Key Store

Maintains an address book of registered public keys in the pool contract for sending private transfers.

## Recovery Scenarios

### Clearing Browser Data

All stored data is lost. On next load:
1. Full sync from RPC (limited by RPC retention window, typically [7 days](https://developers.stellar.org/docs/data/apis/rpc)).
2. Merkle trees rebuilt from synced events.
3. User must re-authenticate for keypair derivation.
4. Note scanning rediscovers received notes.
5. If events are older than retention window, they cannot be recovered.

### Account Switch

If the keys derivation is required, a user will be asked for that. From that moment on, this new account is as well used to scan new notes in the background events processing.

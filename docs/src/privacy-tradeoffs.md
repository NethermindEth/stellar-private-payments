# Contract Event Privacy & Correlation Trade-offs

This document details the privacy guarantees, protocol-inherent correlation surfaces, and public key directory opt-in trade-offs across all smart contract events.

## 1. Protocol-Inherent Transaction Correlation Trade-off

While transfer amounts and note contents are encrypted in zero-knowledge proofs and note ciphertexts, standard Soroban contract calls inherently expose `ExtData` (e.g., `recipient`, `ext_amount`) as public invocation arguments. Furthermore, contract events (`NewCommitmentEvent` and `NewNullifierEvent`) fire synchronously within the same `transact` call.

As a consequence, on-chain observers can correlate:
* **Public Address to Note Commitment**: Deposit and withdrawal public Stellar addresses specified in `ExtData` can be linked to newly created note commitments via transaction ordering and block timestamps.
* **Execution Timing**: Transaction execution timing and block height correlate directly with specific nullifiers and commitment Merkle indexes.

## 2. Public Key Registry Opt-In Trade-off

The `PublicKeyEvent` emitted by `PublicKeyRegistry` deliberately binds a user's public Stellar `Address` to their X25519 `encryption_key` and BN254 `note_key`.

* **Purpose**: Allows senders to resolve a recipient's keys on-chain without out-of-band communication.
* **Opt-In Nature**: Key registration is strictly voluntary. Users who prefer to keep their public address decoupled from their shielded payment keys should skip registry registration and exchange keys directly out-of-band.
* **Blocklist Lookups**: Before each transaction in a blocklist pool, the client asks the RPC for its note key's blocklist path. The request doesn't carry the user's address, but an RPC that also relays the transaction can link the two by timing or IP.

## 3. Event Privacy Classification Summary

| Event Name | Contract Crate | Topics (Indexed) | Data (Payload) | Privacy & Correlation Classification |
|---|---|---|---|---|
| `NewCommitmentEvent` | `pool` | `[Symbol("NewCommitmentEvent"), commitment: U256]` | `index: u32`, `encrypted_output: Bytes` | **Public Data / Correlatable**: Commitment is a blinded Poseidon hash; encrypted output uses fresh OS CSPRNG nonces per note. Correlatable with public transaction args (`ExtData`). |
| `NewNullifierEvent` | `pool` | `[Symbol("NewNullifierEvent"), nullifier: U256]` | *empty* | **Pseudonymous / One-Time Use**: Unlinks spent note from new commitments, but nullifier reuse would break privacy. A [disclosure receipt](./disclosure.md) carries its notes' nullifiers, so its holder can see when they are spent. |
| `LeafAddedEvent` | `asp-membership` | `[Symbol("LeafAdded")]` | `leaf: U256`, `index: u64`, `root: U256` | **Public Protocol Data**: Blinded membership commitment `poseidon2_hash2(note_pubkey, blinding, 1)`. |
| `LeafInsertedEvent` | `asp-non-membership` | `[Symbol("LeafInserted")]` | `key: U256`, `value: U256`, `root: U256` | **Transparency Property / Correlatable**: In ASP blocklist management, `key` is the unblinded note public key. Public blocklist key transparency allows users to verify non-membership. |
| `LeafDeletedEvent` | `asp-non-membership` | `[Symbol("LeafDeleted")]` | `key: U256`, `root: U256` | **Transparency Property**: Key removed from blocklist. |
| `PublicKeyEvent` | `public-key-registry` | `[Symbol("PublicKeyEvent"), owner: Address]` | `encryption_key: Bytes`, `note_key: Bytes` | **Opt-In Public Directory**: Binds public Stellar address to note/encryption public keys for recipient discovery. |

## 4. Unchecked Note Ciphertexts

The proof binds each output commitment, but not the `encrypted_output` attached to it in `NewCommitmentEvent`. A ciphertext can claim an amount its commitment doesn't hold, or be unreadable. This is intentional: it's cheaper and faster than proving each ciphertext matches its note.

* **Readers Must Recheck**: The SDK recomputes the commitment from the decrypted note and ignores notes that don't match. Indexers, wallets, and exchanges that decrypt `encrypted_output` themselves must do the same before crediting a note.
* **GVK Pools**: The proof checks the GVK holder's copy of each note, not the recipient's. A note the GVK holder can audit may still be unreadable by its recipient.

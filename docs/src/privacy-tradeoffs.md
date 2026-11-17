# Contract Event Privacy & Correlation Trade-offs

This document details the privacy guarantees, protocol-inherent correlation surfaces, and public key directory opt-in trade-offs across all smart contract events.

## 1. Protocol-Inherent Transaction Correlation Trade-off

While transfer amounts and note contents are encrypted in zero-knowledge proofs and note ciphertexts, standard Soroban contract calls inherently expose `ExtData` (e.g., `recipient`, `ext_amount`) as public invocation arguments. Furthermore, contract events (`NewCommitmentEvent` and `NewNullifierEvent`) fire synchronously within the same `transact` call.

As a consequence, on-chain observers can correlate:
* **Public Address to Note Commitment**: Deposit and withdrawal public Stellar addresses specified in `ExtData` can be linked to newly created note commitments via transaction ordering and block timestamps.
* **Execution Timing**: Transaction execution timing and block height correlate directly with specific nullifiers and commitment Merkle indexes.

## 2. Public Key Registry Opt-In Trade-off

The `PublicKeyEvent` emitted by `PublicKeyRegistry` binds a user's public Stellar `Address` to their BN254 `note_key` and their encryption key. The `encryption_key` field holds the whole 1216-byte X-Wing (X25519 + ML-KEM-768) public key as one opaque value, which the registry stores as is and only length-checks. Notes are encrypted with HPKE (X-Wing, HKDF-SHA256, ChaCha20-Poly1305), so they stay confidential if either X25519 or ML-KEM-768 holds. The event also carries the owner's SEP-53 signature over the registration message, which covers the whole encryption key and which clients verify before indexing the event. A source cannot produce that signature for keys the owner did not sign, so the binding holds even when the RPC or bootnode is untrusted.

The registry does **not** check that the registrant holds the encryption secret key (a key-encapsulation key cannot sign, and registration needs no proof of it). Registering needs the owner's own authorization, so this only affects the registering account itself. A registrant can publish a key nobody holds (notes sent to them are then unreadable by anyone), or copy someone else's public key (that key's holder can then read amounts and blindings of notes sent to the registrant, but cannot spend them). Equal encryption keys therefore do not imply the same owner, and nothing should treat them as such. Clients must validate the key length and skip malformed events.

* **Purpose**: Allows senders to resolve a recipient's keys on-chain without out-of-band communication.
* **Opt-In Nature**: Key registration is strictly voluntary. Users who prefer to keep their public address decoupled from their shielded payment keys should skip registry registration and exchange keys directly out-of-band. Registration is permanent: the keys registered for an address can't be changed or removed.
* **Blocklist Lookups**: Before each transaction in a blocklist pool, the client asks the RPC for its note key's blocklist path. The request doesn't carry the user's address, but an RPC that also relays the transaction can link the two by timing or IP.

## 3. Event Privacy Classification Summary

| Event Name | Contract Crate | Topics (Indexed) | Data (Payload) | Privacy & Correlation Classification |
|---|---|---|---|---|
| `NewCommitmentEvent` | `pool` | `[Symbol("NewCommitmentEvent"), commitment: U256]` | `index: u32`, `encrypted_output: Bytes` | **Public Data / Correlatable**: Commitment is a blinded Poseidon hash; encrypted output uses fresh OS CSPRNG nonces per note. Correlatable with public transaction args (`ExtData`). |
| `NewNullifierEvent` | `pool` | `[Symbol("NewNullifierEvent"), nullifier: U256]` | *empty* | **Pseudonymous / One-Time Use**: Unlinks spent note from new commitments, but nullifier reuse would break privacy. A [disclosure receipt](./disclosure.md) carries its notes' nullifiers, so its holder can see when they are spent. |
| `LeafAddedEvent` | `asp-membership` | `[Symbol("LeafAdded")]` | `leaf: U256`, `index: u64`, `root: U256` | **Public Protocol Data**: Blinded membership commitment `poseidon2_hash2(note_pubkey, blinding, 1)`. |
| `LeafInsertedEvent` | `asp-non-membership` | `[Symbol("LeafInserted")]` | `key: U256`, `value: U256`, `root: U256` | **Transparency Property / Correlatable**: In ASP blocklist management, `key` is the unblinded note public key. Public blocklist key transparency allows users to verify non-membership. |
| `LeafDeletedEvent` | `asp-non-membership` | `[Symbol("LeafDeleted")]` | `key: U256`, `root: U256` | **Transparency Property**: Key removed from blocklist. |
| `PublicKeyEvent` | `public-key-registry` | `[Symbol("PublicKeyEvent"), owner: Address]` | `encryption_key: Bytes`, `note_key: Bytes`, `owner_signature: BytesN<64>` | **Opt-In Public Directory**: Binds public Stellar address to note/encryption public keys for recipient discovery. The signature is verified against the registration message before indexing. |

## 4. Unchecked Note Ciphertexts

The proof binds each output commitment, but not the `encrypted_output` attached to it in `NewCommitmentEvent`. A ciphertext can claim an amount its commitment doesn't hold, or be unreadable. This is intentional: it's cheaper and faster than proving each ciphertext matches its note.

* **Readers Must Recheck**: The SDK recomputes the commitment from the decrypted note and ignores notes that don't match. Indexers, wallets, and exchanges that decrypt `encrypted_output` themselves must do the same before crediting a note.
* **GVK Pools**: The proof checks the GVK holder's copy of each note, not the recipient's. A note the GVK holder can audit may still be unreadable by its recipient.

## 5. Forward secrecy

### No forward secrecy in case of recipient's private key leak
If a recipient encryption private key is compromised, an attacker is able to decrypt all the past notes addressed to the original private key holder.

### Forward secrecy in case of sender's private key leak
If a sender's private key is compromised, the ciphertexts produced by the sender are safe (forward secrecy
under the assumption of proper randomness used, see 9.7.4 and 9.7.5 in https://datatracker.ietf.org/doc/rfc9180/).

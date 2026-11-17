# Post-quantum readiness map

SPP is not yet PQ ready. But the most critical part (namely, notes encryption in *non-GVK* pools) is protected against Harvest Now Decrypt Later (HNDL) risk.

## Parts exposed to a cryptographically relevant quantum computer (CRQC)

### ✅ Secrets derivation

This part is plausibly PQ ready. 
The secrets are derived from the bytes of Stellar signature. Under CRQC Shor's attack an attacker recovers the signing scalar of Ed25519 signature scheme used by Stellar but the deterministic nonce is `H(prefix ‖ M)` with `prefix` from `SHA-512(seed)`, so the attacker's signature on the same message differs from the wallet's and derives different keys. It holds while the signature never leaves the client.

Notes encryption implements HPKE (X-Wing, HKDF-SHA256, ChaCha20-Poly1305) in base mode (X-Wing is still in a draft https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem but HPKE scheme specified in IETF RFC 9180 https://datatracker.ietf.org/doc/rfc9180/).
This part is the most important one as it protects against Harvest Now Decrypt Later (HNDL) risk (except GVK-enabled pools, see [GVK pools](#-gvk-pools) below).

Secrets in memory are zeroed at Rust SDK level. SDK users must pay attention to any secrets exposed in their app and apply respective protection practices accordingly.
Note: client storage (SQLite as a default) symmetric encryption will be resolved soon (https://github.com/NethermindEth/stellar-private-payments/issues/71).

### ✅ Transport

Key exchange of the connection to the RPC (and bootnode) can be hybrid post-quantum (X25519MLKEM768), but only if the server supports it.

* **Native (CLI, Rust SDK)**: the TLS client (`rustls` with `aws-lc-rs`) offers X25519MLKEM768 as its preferred key exchange group. A server without hybrid support silently falls back to classical X25519, and nothing in the SDK reports or blocks that downgrade.
* **Browser**: requests go through the browser's own TLS stack, which the app cannot configure. Current Chrome, Edge and Firefox offer X25519MLKEM768 by default.
* Server certificates and handshake signatures stay classical. That does not matter for HNDL, which concerns the confidentiality of recorded traffic, but it does not protect against an active attacker with a CRQC.
* The RPC traffic carries only public chain data, and note plaintext is protected by the note encryption itself, so the transport mainly affects the privacy of who queries what (see [privacy tradeoffs](privacy-tradeoffs.md)). Use an RPC provider that supports hybrid key exchange.

### 🚨 GVK pools

In a pool with a Global View Key, each note comes with a memo that encrypts the note's `(pk, amount, blinding)` inside the circuit under the admin's Baby JubJub public key `D` (ECIES, see [Global View Key](./global_view_key.md)). The memo is public on-chain. Baby JubJub security rests on the elliptic-curve discrete logarithm, which a CRQC solves with Shor's algorithm. An attacker then recovers the admin's private scalar from `D` and decrypts every memo, past and future. Memos recorded today can be decrypted later (HNDL), so the hybrid note encryption above does not protect the notes of a GVK pool.

What stays safe: the memo holds the note's public key, not its private key, and GVK gives no spending authority, so funds are not exposed by this. What is lost is privacy: amounts, blindings and, in traceable mode, the link between inputs and outputs. Fixing it needs a post-quantum layer around the memo that the proof binds to the note, which is a circuit change.

### 🚨 Proof system

Currently used Groth16 (which becomes unsound under CRQC) limits what SPP can use as a hash (currently Poseidon2, can be weak under CRQC) for Merkle trees and Global View Key encryption (which is also broken under CRQC).
Note: pools deployed with GVK will loose privacy under CRQC but users will keep their funds as GVK doesn't give spending authority.
Unsound proof system can potentially lead to notes creation without the balance equation holding (i.e. "money printing").

### 🚨 Stellar-specific

TX signing and governance of contracts (critical for user funds) depends on the ongoing Stellar PQ migration and SPP will be updated as soon as new schemes are available.

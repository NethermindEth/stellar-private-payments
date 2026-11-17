# Post-quantum readiness map

SPP is not yet PQ ready. But the most critical part (namely, notes encryption in *non-GVK* pools) is protected against Harvest Now Decrypt Later (HNDL) risk.

## Parts exposed to a cryptographically relevant quantum computer (CRQC)

### ✅ Secrets derivation

This part is plausibly PQ ready. 
The secrets are derived from the bytes of Stellar signature. Under CRQC Shor's attack an attacker recovers the signing scalar of Ed25519 signature scheme used by Stellar but the deterministic nonce is `H(prefix ‖ M)` with `prefix` from `SHA-512(seed)`, so the attacker's signature on the same message differs from the wallet's and derives different keys. It holds while the signature never leaves the client.

Notes encryption implements HPKE (X-Wing, HKDF-SHA256, ChaCha20-Poly1305) in base mode (X-Wing is still in a draft https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem but HPKE scheme specified in IETF RFC 9180 https://datatracker.ietf.org/doc/rfc9180/).
This part is the most important one as it protects against Harvest Now Decrypt Later (HNDL) risk (except GVK-enabled pools where the TODO).

Secrets in memory are zeroed at Rust SDK level. SDK users must pay attention to any secrets exposed in their app and apply respective protection practices accordingly.
Note: client storage (SQLite as a default) symmetric encryption will be resolved soon (https://github.com/NethermindEth/stellar-private-payments/issues/71).

### ✅ Transport

Key exchange of the connection to the RPC (and bootnode) can be hybrid post-quantum (X25519MLKEM768), but only if the server supports it.

* **Native (CLI, Rust SDK)**: the TLS client (`rustls` with `aws-lc-rs`) offers X25519MLKEM768 as its preferred key exchange group. A server without hybrid support silently falls back to classical X25519, and nothing in the SDK reports or blocks that downgrade.
* **Browser**: requests go through the browser's own TLS stack, which the app cannot configure. Current Chrome, Edge and Firefox offer X25519MLKEM768 by default.
* Server certificates and handshake signatures stay classical. That does not matter for HNDL, which concerns the confidentiality of recorded traffic, but it does not protect against an active attacker with a CRQC.
* The RPC traffic carries only public chain data, and note plaintext is protected by the note encryption itself, so the transport mainly affects the privacy of who queries what (see [privacy tradeoffs](privacy-tradeoffs.md)). Use an RPC provider that supports hybrid key exchange.

### 🚨 Proof system

Currently used Groth16 (which becomes unsound under CRQC) limits what SPP can use as a hash (currently Poseidon2, can be weak under CRQC) for Merkle trees and Global View Key encryption (which is also broken under CRQC).
Note: pools deployed with GVK will loose privacy under CRQC but users will keep their funds as GVK doesn't give spending authority.
Unsound proof system can potentially lead to notes creation without the balance equation holding (i.e. "money printing").
TODO CRQC will also - what about registry of pubkeys here?

### 🚨 Stellar-specific

TX signing and governance of contracts (critical for user funds) depends on the ongoing Stellar PQ migration and SPP will be updated as soon as new schemes are available.

# Post-quantum readiness map

SPP is not yet PQ ready. But the most critical part (namely, notes encryption in *non-GVK* pools) is protected against Harvest Now Decrypt Later (HNDL) risk.

## Parts exposed to a cryptographically relevant quantum computer (CRQC)

### ✅ Secrets derivation

This part is plausibly PQ ready. 
The secrets are derived from the bytes of Stellar signature. Under CRQC Shor's attack an attacker recovers the signing scalar of Ed25519 signature scheme used by Stellar but the deterministic nonce is `H(prefix ‖ M)` with `prefix` from `SHA-512(seed)`, so the attacker's signature on the same message differs from the wallet's and derives different keys. It holds while the signature never leaves the client.

Notes encryption implements hybrid X-Wing (X25519 + ML-KEM-768) KEM through HPKE base mode
This part is the most important one as it protects against Harvest Now Decrypt Later (HNDL) risk (except GVK-enabled pools).

Secrets in memory are zeroed at Rust SDK level. SDK users must pay attention to any secrets exposed in their app and apply respective protection practices accordingly.
Note: client storage (SQLite as a default) symmetric encryption will be resolved soon (https://github.com/NethermindEth/stellar-private-payments/issues/71).

### 🚧 Transport

It will be solved with an upgade of the networking libs soon.

### 🚨 Proof system

Currently used Groth16 (which becomes unsound under CRQC) limits what SPP can use as a hash (currently Poseidon2, can be weak under CRQC) for Merkle trees and Global View Key encryption (which is also broken under CRQC).
Note: pools deployed with GVK will loose privacy under CRQC but users will keep their funds as GVK doesn't give spending authority.
Unsound proof system can potentially lead to notes creation without the balance equation holding (i.e. "money printing").

### 🚨 Stellar-specific

TX signing and governance of contracts (critical for user funds) depends on the ongoing Stellar PQ migration and SPP will be updated as soon as new schemes are available.

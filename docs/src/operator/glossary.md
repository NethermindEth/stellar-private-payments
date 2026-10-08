# Glossary

The manual uses one term for each concept. The code name follows in parentheses where it
differs.

| Term | Meaning |
| --- | --- |
| Admin | The address stored as a contract's admin (`Admin`). One admin account usually administers every pool and tree in a deployment. |
| Admin account | A Stellar account that needs M of its N signers on every transaction, used as the admin. |
| Admin call | A transaction that calls an admin-only entry point, signed by the admin. |
| Allowlist | The tree of approved members (`asp-membership`). A pool with the allowlist policy accepts only spenders whose leaf is in it. |
| ASP | Association set provider: whoever maintains a pool's allowlist or blocklist. |
| ASP secret | A per-user value derived from the user's key-derivation signature (`membership_blinding`). It blinds the user's allowlist leaf. |
| Authority | The party a user sends a disclosure receipt to. Used only for selective disclosure. |
| Blocklist | The sparse Merkle tree of blocked note public keys (`asp-non-membership`). A pool with the blocklist policy refuses spenders whose key is in it. |
| Bootnode | A service that archives a deployment's contract events and serves them to clients that fall behind the RPC's event retention. |
| Circuit | The program a proof is about. Each policy and GVK mode has its own transaction circuit. |
| Commitment | The hash of a note that the pool stores in its commitment tree. |
| Deployer | The account that pays for the deployment. It keeps no power once the contracts name another admin. |
| Deployment ledger | The ledger a contract was deployed in. Clients and the bootnode read its events from there. |
| Encryption key | The X25519 key pair a user receives notes with. Senders encrypt each note to the recipient's encryption public key. |
| GVK | Global View Key: a Baby JubJub key pair fixed in a `pool-gvk` pool at construction. Every note in that pool is encrypted to the GVK public key. |
| GVK holder | Whoever holds a GVK private key, and so can decrypt that pool's notes. The GVK holder need not be the admin. |
| KDF domain | Key derivation function domain (`kdf_domain`): a string, fixed per deployment, inside the message users sign to derive their note key, encryption key, and ASP secret. |
| Leaf | An entry in a tree. An allowlist leaf is the hash of a note public key and an ASP secret. |
| Manifest | The file `deploy.sh` writes, `deployments/NETWORK/deployments.json`. Clients read the deployment's contract addresses from it. |
| Note | A private balance: an amount, the owner's note public key, and a random blinding. |
| Note key | The key pair that owns notes. Its public half, the note public key, is what the ASP screens. |
| Nullifier | A value derived from a note and its owner's note private key. The pool records it when the note is spent, which stops a second spend. |
| Operator | Whoever runs a deployment: the reader of this manual. |
| Pause file | A pre-signed authorization of one `pause_deposits` call on one pool, which its holder can submit with no signer present. The admin page calls these pause authorizations. |
| Policy | The ASP checks a pool requires: `none`, `allowlist`, `blocklist`, or `allowlist-blocklist` (`policy_flags`). |
| Pool | The contract that holds one token and accepts deposits, transfers, and withdrawals (`pool`, or `pool-gvk` with a GVK). |
| Proof | A zero-knowledge proof: it shows that a transaction follows the circuit's rules without revealing the notes and keys behind it. |
| Proving key, verifying key | The pair of keys a circuit needs. Clients prove with the proving key; the verifier checks with the verifying key. Together they are the circuit keys. |
| Re-point | Switching a pool to another allowlist or blocklist. |
| Root | The hash at the top of a tree. It changes with every insert, and a proof names the roots it was built against. |
| Tree | An allowlist or a blocklist. The pool's own tree of commitments is the commitment tree. |
| Tree code | The Wasm hash a tree runs. A pool accepts only trees whose code matches the hashes fixed at its construction. |
| Trusted setup ceremony | The process that generates circuit keys. Whoever learns its secret randomness can forge proofs. Several people contribute in turn, and the keys are safe if at least one of them discards their share. |
| Verifier | The contract that checks a proof against the verifying key built into it. |

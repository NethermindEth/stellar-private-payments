## Security

If you believe you have found a security vulnerability in any Nethermind-owned repository that meets [CVE's definition of a security vulnerability](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryVulnerability), please report it to us as described below.
We ask you to please not publicly disclose any details of the vulnerability until we have had an opportunity to investigate and address it.

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use GitHub's  [report vulnerability](https://github.com/NethermindEth/stellar-private-transactions/security/advisories/new) tool to create a draft advisory.
Please include as much information as you can provide (listed below) to help us better understand the nature and scope of the possible issue:

* Type of issue.
* Source files affected by the issue.
* Location of source code (tag/branch/commit or direct URL).
* Step-by-step instructions to reproduce the issue and any additional configuration that might be needed.
* Severity of the issue.

## Fixes

We will release fixes for verified security vulnerabilities.
We expect to publish vulnerabilities using GitHub [security advisories](https://github.com/NethermindEth/stellar-private-transactions/security/advisories).

## Logging Security & Privacy Model

To protect user confidentiality during transaction proving and indexing, the SDK implements a strict **two-tier data privacy model** for all logging and telemetry.

### The Invariant
* **Tier-0 Secrets (NEVER logged)**: Cryptographic private keys, seeds, signatures, circuit witnesses, and membership blinding factors must **never** be output to logs, spans, or telemetry sinks under any circumstance, profile, or runtime setting.
* **Tier-1 Sensitive Fields (Redacted by default)**: User addresses, transfer amounts, note commitments, and transaction nullifiers are wrapped in a protective `Sensitive<T>` container. By default, they render as `<redacted>`.

### Debug Log Warning
> [!WARNING]
> In debug builds (i.e., built with `release-with-logs` or under native tests), Tier-1 sensitive values can be optionally revealed at runtime using the `revealSensitive` setting for developer diagnostics. **Never share raw verbose debug logs publicly**, as they may expose transaction amounts and address correlations.

## Encrypted local storage

The native CLI and browser private vault encrypt SQLite pages with SQLite3 Multiple
Ciphers (ChaCha20 with per-page authentication), using random 256-bit database
keys. The native CLI seals its key under a password with Argon2id (64 MiB,
three iterations, one lane) and XSalsa20-Poly1305. KDF costs read from native
records are capped at that profile.

The browser uses Freighter alone. A verified SEP-0053 signature over an
origin-, account-, and random-salt-bound message feeds HKDF-SHA-256. The resulting
256-bit secret directly seals the random database key with XSalsa20-Poly1305,
using a fresh 24-byte nonce. New setup verifies two matching signatures before
saving a record; subsequent unlocks need one approval. The database key remains
inside the storage worker. The page necessarily handles the signature and wrapping
secret transiently; neither is persisted or logged. There is no browser password
or passkey fallback. Native CLI password support is unchanged.

The browser opens `spp.public.db` without a password. It contains public chain
events, derived commitments/nullifiers/registered keys, indexing progress, and
explorer/bootnode settings. Those values, including the contracts followed and
configured URLs, are readable in a copied browser profile. Do not put credentials
in these URLs. Generic settings, GVK authority material, account associations,
private keys, decrypted notes, note amounts/blindings/nullifier associations,
disclaimer acceptances, and private operation history remain in the encrypted
`spp.encrypted.db` vault. Private worker requests fail while that vault is locked.

The vault retains a chain snapshot to preserve its internal foreign keys. On the
first successful unlock, an explicit allowlist seeds the public cache from the
vault; no private tables are exported. On every unlock, cached chain events are
merged by event ID and contract address and their progress is committed in the
same vault transaction. Existing conflicting events are rejected. New public
chain data is not confidential or authenticated by at-rest encryption; existing
chain/proof validation remains necessary. Public ingestion commits to the cache
first, then the open vault, so a crash between writes can be replayed on unlock.
Private note scanning resumes only after unlocking. The native CLI continues to
use a single encrypted database.

### Wallet access and recovery

The enrolled Freighter account is the sole browser unlock method. Settings shows
its address. Losing access to that account prevents unlocking the vault. A
compromised wallet signing key can reproduce the signature and decrypt a copied
vault and its key record. A malicious site may ask the user to sign the same
message: SEP-0053 does not enforce origin binding at the wallet level. Only approve
the local-storage message on the trusted app origin. Treat that signature as a
decryption secret.

Browser storage supports the current wallet envelope and migration from the
original plaintext database. Intermediate development-only password/passkey
browser formats are unsupported; use an explicit local reset for those profiles.
Existing encrypted data is never silently overwritten. Interrupted wallet setup
or plaintext migration resumes with the saved wallet envelope and the same key.

Native password changes do not rotate the database key or revoke older backups
and copied envelopes. True key rotation is not implemented. A destructive reset
generates a new key on the next setup but cannot erase previous copies.

Reset deletes local settings, history and keys. Chain data and wallet-derived
keys can be recovered through sync and onboarding, but local-only settings and
history should not be assumed recoverable. Keep database files and their matching
key records together when backing up a closed profile; the browser app has no
built-in local-data export. Missing credentials require recovery or explicit
reset, never automatic recreation.

### Migration and deletion limits

Migration verifies a copy into an encrypted database before removing the active
plaintext files. Deletion/unlinking **is not secure erasure**: earlier file blocks,
browser/profile backups, snapshots and container layers may retain plaintext.
Neither native nor browser migration overwrites all historic copies. Protect the
storage device with full-disk encryption and handle old backups according to
your retention policy. SQLite encryption cannot protect an unlocked application
from malicious same-origin JavaScript, a compromised browser/OS, or memory reads.

### Metadata and locking

Unencrypted envelope metadata contains the wallet address, origin, salt and sealed
key. Browser
auto-lock preferences and account/signing Stellar addresses in `localStorage`
are also stored unencrypted. These are not decryption
secrets but can fingerprint a profile.

Browser locking requests storage closure and reloads the page, with a three-second
fallback reload if the worker does not acknowledge closure. Auto-lock waits for guarded
foreground work (including key derivation, registration, admin operations and
wallet setup), then starts a fresh inactivity interval. Guarded work
can defer an expired idle lock by at most ten additional minutes; a stuck wallet
prompt or transaction marker cannot keep storage unlocked indefinitely. Deadlines
use a monotonic clock. Locking starts as soon as the private vault opens, including during onboarding. Locking clears the page's private state by
reloading; the page can resume public syncing without an unlock prompt when a
runtime is connected. Private balances and history remain unavailable until the
next explicit unlock. SQLite's synchronous transactions complete before the
worker handles close. A forced browser/process termination instead relies on
rollback-journal recovery. The Chromium regression suite terminates a real worker
after an uncommitted OPFS write to exercise this path.

The CLI holds an advisory exclusive lock on its data directory for each storage
command, before preflight, migration or password updates. Independent native SDK
embedders must still enforce exclusive ownership during open/migration and key
record updates; SQLite locks alone do not protect an immutable preflight.
Advisory locks cannot constrain programs that ignore them. Keep native data
directories and password files private (`0700` directories, `0600` files).
Password-file permissions are not automatically changed by the SDK.

### Backend and release qualification

Supported native and browser builds compile the same hash-pinned SQLite3MC
amalgamation via `sdk/native/sqlite3mc_source.rs`. The WASM builder uses
`sqlite-wasm-rs` shims and a Cargo link override; the crate's bundled older cipher
source is not the supported browser backend. Build using the repository scripts.
Native and WASM configure extension loading out. The vendored SAH VFS allows only
one open handle per logical filename, so native multi-handle APIs must not be
assumed supported on WASM. Backend upgrades, cross-platform file portability,
and additional release architectures need separate qualification.

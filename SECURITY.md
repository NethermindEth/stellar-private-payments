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

The native CLI and browser encrypt SQLite pages with SQLite3 Multiple Ciphers
(ChaCha20 with per-page authentication). A random database key is sealed under a
password using Argon2id (64 MiB, three iterations, one lane) and an authenticated
XSalsa20-Poly1305 envelope. Key records are readable before unlocking and contain
public parameters plus sealed keys. Passwords and raw database keys are not
written to those records. Supported record KDF costs are bounded by the current
production profile; increasing costs requires an explicit format/compatibility
decision.

In the browser, Freighter and passkeys are optional independent unlock methods.
Each grants access to the same database key. Security therefore depends on every
enrolled account/device, not just the password. Freighter signatures and WebAuthn
PRF outputs used to unlock storage are secrets. The app checks reproducibility
before enrolling either method. Use Settings → Local Data to inspect, replace,
or remove optional methods with the current password. One credential per method
is supported; replacing a passkey replaces access on this browser's database,
not on another device's database or passkey provider.

### What changing or removing access means

Changing a password re-seals the existing database key. **It does not rotate the
database key**, disable other methods, invalidate an old copy of the key record,
or revoke a leaked database key. Removing/replacing Freighter or passkey access
only updates the current key record. Anyone with an older complete backup and
its former unlock method can still decrypt that copy. True key rotation with
re-encryption is not implemented. Treat a copied database key as a compromise;
a destructive local reset creates a fresh key but cannot erase previous copies.

Reset deletes local settings, history and keys. Chain data and wallet-derived
keys can be recovered through sync and onboarding, but local-only settings and
history should not be assumed recoverable. Back up the encrypted database and
its matching key record together while the database is closed. If encrypted
data exists without a readable password record, the browser requires explicit
recovery/reset and refuses to overwrite it as a new database. If an enrolled
Freighter or passkey envelope survives, unlocking with it allows setting a new
password without deleting data or other methods. This recovery route is enabled
only after a successful optional-method unlock with an absent password record;
it cannot replace an existing password. The temporary worker key is zeroized
when recovery completes or the worker closes. Without a surviving unlock method
or complete backup, reset remains destructive.

### Migration and deletion limits

Migration verifies a copy into an encrypted database before removing the active
plaintext files. Deletion/unlinking **is not secure erasure**: earlier file blocks,
browser/profile backups, snapshots and container layers may retain plaintext.
Neither native nor browser migration overwrites all historic copies. Protect the
storage device with full-disk encryption and handle old backups according to
your retention policy. SQLite encryption cannot protect an unlocked application
from malicious same-origin JavaScript, a compromised browser/OS, or memory reads.

### Metadata and locking

Unencrypted envelope metadata identifies enabled methods, including wallet
address, passkey credential ID, origin/RP ID, salts and KDF parameters. Browser
auto-lock preferences are also stored unencrypted. These are not decryption
secrets but can fingerprint a profile.

Browser locking closes storage and reloads the page. Auto-lock waits for guarded
foreground work (including key derivation, registration, admin operations and
unlock-method changes), then starts a fresh inactivity interval. Background sync
is stopped when locking; SQLite's synchronous transactions complete before the
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

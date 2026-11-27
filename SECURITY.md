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

## Browser Memory Model

* **Same-origin scripts are trusted.** A script running in the app's origin can call the SDK, wrap the wallet signer, or read WASM linear memory, so it can obtain every secret. Both app pages ship a Content-Security-Policy that only allows same-origin scripts and the hashed import map.
* **The app refuses to run inside a frame.** GitHub Pages cannot send `frame-ancestors` or `X-Frame-Options`, so each page hides itself and stops before any app code runs when it is not the top-level window.
* **Rust-owned secrets are zeroized on drop**: privacy keys, key-derivation signatures, the storage key and the GVK authority key.
* **The browser build wipes every heap block when it is freed**, so copies Rust leaves behind are cleared too: worker message buffers, `Vec` growth, serde and formatting temporaries, and SQLite's freed pages. Stack copies are not covered.
* **Copies outside Rust ownership are not wiped**:
  * Worker messages on the JS side: the serialized `Uint8Array` the sender posts and the browser's structured-clone copies. These carry the storage key, and the note private key and blindings on their way from the storage worker through the main thread to the prover worker.
  * JS strings, which are immutable: the wallet's `signMessage` reply, `Account.aspSecret()`, and a GVK authority key pasted on the admin page.
  * Browser process memory: swap, crash dumps and devtools heap snapshots.
* **Locking storage reloads the page**, discarding the WASM instances and the JS heap along with any copies left in them.
* **A main-thread panic locks storage too.** A Rust panic traps the WASM instance without running destructors, leaving live secrets in its memory. The SDK fires `PANIC_EVENT` on `globalThis`, and the app marks storage locked and reloads the page if storage is open, opening or locking. A worker panic is not reported to the page; the worker's memory is only reachable from that worker.
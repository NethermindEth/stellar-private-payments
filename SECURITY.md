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
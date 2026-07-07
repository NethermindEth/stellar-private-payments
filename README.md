# Private Payments for Stellar

[![Deployment](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/deployment.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/deployment.yml)
[![Lint](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/linter.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/linter.yml)
[![Build](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/build-and-test.yml)
[![Dependencies](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/dependency-audit.yml)
[![UB](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/ub-detection.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/ub-detection.yml)
[![Coverage](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/coverage.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-payments/actions/workflows/coverage.yml)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=flat&logo=telegram&logoColor=white)](https://t.me/stellar_privacy)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/groups/18809039/)

> [!WARNING]
> This project is a **Work in progress (WIP)**. It is intended to serve as **a reference implementation** of privacy pools for Stellar. The code has not yet been audited and should not be used in production environments with real assets as of now. The security hardening work is planned. Expect breaking changes and necessity to clear your local storage for the demo app/cli until the first stable release.

A privacy-preserving payment system for the Stellar network using zero-knowledge proofs. This implementation enables users to deposit, transfer, and withdraw tokens while maintaining transaction privacy through Groth16 proofs.

The system incorporates **Association Set Provider (ASPs)** as a control mechanism to provide illicit activity safeguards through association sets. ASPs maintain membership and non-membership Merkle trees that allow proving whether specific deposits are part of approved or blocked sets, enabling pool operators to enforce administrative controls without compromising user privacy.

## Features

- **Private Payments**: Deposit, transfer, and withdraw tokens without revealing transaction amounts or sender/receiver relationships
- **Zero-Knowledge Proofs**: Groth16 proofs generated via Circom circuits
- **Administrative Controls**: ASP-based membership and non-membership proofs for illicit activity safeguards
- **Browser-Based Proving**: Client-side proof generation using WebAssembly
- **Stellar Integration**: Built on Soroban smart contracts

## Demo Application
[The demo application](https://nethermindeth.github.io/stellar-private-payments/) consists on three main parts:
- **Frontend**: Provides a nice user interface for interacting with the system. 
- **Circuits**: Where the real zk-magic happens and constraints are defined.
- **Smart Contracts**: They define the state of the system, and how transactions are processed.

The Frontend includes the [user-facing part](#transaction-flow) and an example of an [ASP admin page](#asp-admin-page) which will be separated according to roles in the main application.

The demo app demonstrates integration of the Stellar Private Payments [JS/TS SDK](https://github.com/NethermindEth/stellar-private-payments/tree/main/sdk/web).

### Architecture Overview

#### Transaction Flow

1. **Deposit**: User deposits tokens into the pool, creating a commitment (UTXO). No input notes are spent, creates output notes.
2. **Withdraw**: User proves ownership of commitments and withdraws tokens. Inputs notes are spent, no output notes are created.
3. **Transfer**: User spends existing commitments and creates new ones, all done privately.  Input notes are spent, and output notes under a new public key are created.
4. **Transact**: Enables advanced users with experience on privacy-preserving protocols to generate their own transactions. Spending, creating and transferring notes at will.

#### ASP Admin Page

This is [the administrative control panel](https://nethermindeth.github.io/stellar-private-payments/admin.html) for managing the **Association Set Provider (ASP)** membership trees. It allows you to:

1. **Add/insert public keys** to the ASP membership tree - Controls which public keys are approved
2. **Manage the exclusion list** - Block specific public keys via the non-membership Merkle tree

This provides **illicit activity safeguards** while maintaining user privacy. The ASP membership trees work with the zero-knowledge proofs to prove that deposits either belong to approved accounts or don't belong to blocked accounts—without compromising privacy.

The admin has the option of toggling the "Admin-Only Leaf Insert", It's enabled by default which restricts only the admin to insert membership leaves but when disabled by the admin, anyone can insert membership leaves.

> [!WARNING]
> Disabling "Admin-Only Leaf Insert" removes the access-control safeguard on the ASP membership tree. Any party will be able to add themselves (or others) to the approved set without admin approval, bypassing the intended illicit-activity safeguards. Only disable this in a controlled demo or testing environment—never in production.

#### Zero-Knowledge Circuits

The main transaction circuit proves:
- Ownership of input UTXOs (knowledge of private keys)
- Correct nullifier computation (prevents double-spending)
- Valid Merkle proofs for input commitments
- Correct output commitment computation
- Balance conservation (inputs = outputs + public amount)
- ASP membership/non-membership proofs

#### Smart Contracts

- **Pool**: Main contract handling deposits, transfers, and withdrawals
- **Circom Groth16 Verifier**: On-chain verification of ZK proofs
- **ASP Membership**: Merkle tree of approved public keys
- **ASP Non-Membership**: Sparse Merkle tree for exclusion proofs
- **Public key registry**: A public address book mapping Stellar addresses to user's SPP public keys. \
  (allows transfers by using just a standard Stellar address)

## Install the CLI

The `spp` command-line tool can be installed with a single command:

```bash
curl -fsSL https://nethermindeth.github.io/stellar-private-payments/install.sh | sh
```

This downloads the release binary for your platform (Linux/macOS, x86_64/aarch64),
verifies its checksum, installs `spp` to `~/.local/bin`, and provisions the runtime
`dist` data (circuits, proving key, license/notice texts). Then run `spp --help`.

To install a specific release

```bash
curl -fsSL https://nethermindeth.github.io/stellar-private-payments/install.sh | sh -s -- --version v0.1.0
```

or the latest prerelease

```bash
curl -fsSL https://nethermindeth.github.io/stellar-private-payments/install.sh | sh -s -- --pre
```

CLI demonstrates integration of the Stellar Private Payments [Rust SDK](https://github.com/NethermindEth/stellar-private-payments/tree/main/sdk/pool).

## Limitations

As a work-in-progress, this implementation has several limitations to be resolved in the nearest future:

- **Stellar Events retention**: The app relies heavily on Stellar events. But RPC nodes only store events for a small retention window (7 days). This means that the demo will not work for users onboarded after 7 days of contract deployment because they couldn't re-play events history. But a user who onboarded within 7 days from the contracts deployment and keeps their app tab open in a browser, can use the app without a reset as the events digestion happens in the background.
- **Not Audited**: The code has not undergone security audits.
- **Error Handling**: Error handling may not cover all edge cases.
- **Browser storage** for the storage the app uses SQLite relying on [OPFS](https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system). Basically, the data is stored on the file system as some files with opaque names. Some antiviruses and other software may accidentally delete them. Nevertheless, losing the local state is not critical - all keys are deterministically derived from the wallet-signed message. Only the local app settings and the history of operations (executed by a user) are lost in this case but it doesn't prevent from the new onboarding of the same user and restoring thus an access to pooled tokens.


## AI tools disclosure
The content published here may have been refined/augmented by the use of large language models (LLM), computer programs designed to comprehend and generate human language. However, any output refined/generated with the assistance of such programs has been reviewed, edited and revised by Nethermind.


## License

This repository contains **source code** provided under a mixed license structure (Apache 2.0 and GPLv3).

Most of the source code is licensed under the Apache License, Version 2.0. See `LICENSE` for details.

The exception is `circuits/build.rs` which is licensed separately under the GNU Lesser General Public License v3.0. See `circuits/LICENSE` for details.

### Responsibility of Deployers

The `dist/` directory and its contents (including compiled WebAssembly circuits, keys, and bundled JavaScript) are **generated artifacts** produced by the build process. They are not checked into this repository.

If you compile, build, or deploy this project (e.g., hosting the `dist/` folder on a web server), **you become the distributor** of those binary artifacts. It is your responsibility to:
1.  Ensure all generated artifacts comply with their respective licenses (specifically the LGPLv3 requirements for compiled circuits).
2.  Include the appropriate `LICENSE` and `NOTICE` files in your deployment directory.
3.  Make the source code available to your end-users as required by the LGPLv3 (if you are distributing the compiled circuits).

The maintainers of this repository provide the source code "as is" and assume no responsibility for the downstream builds or deployments.

## Would like to contribute?

Please check [the issues](https://github.com/NethermindEth/stellar-private-payments/issues).
If you're an external contributor, please check the issues with the label `contributors-friendly`.
See also [Contributing](./CONTRIBUTING.md).

## Credit

Credit goes to Horizen Labs for their [Poseidon2 implementation](https://github.com/HorizenLabs/poseidon2), which is integrated into this repository.

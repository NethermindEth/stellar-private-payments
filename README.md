# Private Transactions for Stellar

[![Docs](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/docs.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/docs.yml)
[![Lint](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/linter.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/linter.yml)
[![Build](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/build-and-test.yml)
[![Dependencies](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/dependency-audit.yml)
[![UB](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/ub-detection.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/ub-detection.yml)
[![Coverage](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/coverage.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/coverage.yml)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Disclaimer**: This project is a **Proof of Concept (PoC)** and prototype implementation. It is intended for research and educational purposes only. The code has not been audited and should not be used in production environments with real assets.

A privacy-preserving payment system for the Stellar network using zero-knowledge proofs. This implementation enables users to deposit, transfer, and withdraw tokens while maintaining transaction privacy through Groth16 proofs.

The system incorporates **Administrative Service Providers (ASPs)** as a control mechanism to provide illicit activity safeguards through association sets. ASPs maintain membership and non-membership Merkle trees that allow proving whether specific deposits are part of approved or blocked sets, enabling pool operators to enforce administrative controls without compromising user privacy.

## Features

- **Private Transactions**: Deposit, transfer, and withdraw tokens without revealing transaction amounts or sender/receiver relationships
- **Zero-Knowledge Proofs**: Groth16 proofs generated via Circom circuits
- **Administrative Controls**: ASP-based membership and non-membership proofs for illicit activity safeguards
- **Browser-Based Proving**: Client-side proof generation using WebAssembly
- **Stellar Integration**: Built on Soroban smart contracts

## Demo Application
The demo application consists on three main parts:
- **Frontend**: Provides a nice user interface for interacting with the system. 
- **Circuits**: Where the real zk-magic happens and constraints are defined.
- **Smart Contracts**: They define the state of the system, and how transactions are processed.

If you want to try it out:

1. Install dependencies
    ```bash
      make install
    ``` 
   

2. Compile the project, including circuit tests:
    ```bash
      make circuits-build # or BUILD_TESTS=1 cargo build
    ```
   

3. Deploy the contracts to a Stellar network:
    ```bash
    ./scripts/deploy.sh <network> \                     # e.g. testnet
      --deployer <identity> \                           # Must be added in stellar-cli keys
      --asp-levels 10 \                                 # Number of levels in the ASP trees
      --pool-levels 10 \                                # Number of levels in the pool Merkle tree
      --max-deposit 1000000000 \                        # Maximum deposit amount (in Stroops)
      --vk-file scripts/testdata/policy_test_vk.json # Verification key file
    ```
   If you already have deployed contracts, make sure their addresses are updated in `scripts/deployments.json`.

4. Serve frontend
    ```bash
      make serve
    ```
    Open `http://localhost:8080` in your browser. You might want to open the console (_Shift + Ctrl + I_) to see the logs.
    You might need to delete the browser cache from previous runs. Go to `Application` -> `Clear storage`.


5. The pool is ready to use. But you will need to populate the ASP membership smart contracts with some public keys. You can do it directly from the stellar-cli:
    ```bash
    stellar contract invoke --id <CONTRACT_ADDRESS> --source-account <ASP_ADMIN_ACCOUNT> -- insert_leaf --leaf <LEAF_VALUE> # See circuit for leaf format
    ```
    Or, directly access `http://localhost:8080/admin.html` and use the UI to add public keys.
    Please note that the admin UI allows deriving keys for ANY account.
    But insertion MUST be signed by the ASP admin account.
    You can add your Freighter account to your Stellar-cli keys with `stellar keys add <NAME_FOR_ACCOUNT> --seed-phrase`.
    This will prompt you to type your seed phrase and will enable you to deploy contracts with the same account you have on your browser wallet.


6. Go back to `http://localhost:8080` and try it out!

### Architecture Overview

#### Transaction Flow

1. **Deposit**: User deposits tokens into the pool, creating a commitment (UTXO). No input notes are spent, creates output notes.
2. **Withdraw**: User proves ownership of commitments and withdraws tokens. Inputs notes are spent, no output notes are created.
3. **Transfer**: User spends existing commitments and creates new ones, all done privately.  Input notes are spent, and output notes under a new public key are created.
4. **Transact**: Enables advanced users with experience on privacy-preserving protocols to generate their own transactions. Spending, creating and transferring notes at will.

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

## Limitations

As a proof of concept, this implementation has several limitations:

- **No Groth16 Ceremony**: The Common Reference String (CRS) was not generated doing a decentralized ceremony.
- **Single circuit support**: Now the demo only showcases a single circuit (2 inputs, 2 outputs). Support for multiple circuits might be added in the future.
- **No Stellar Events**: The demo relies heavily on Stellar events. But RPC nodes only store events for a small retention window (7 days). This means that the demo will not work for longer periods of time. It requires a dedicated indexer serving events to users.
- **Decimal support**: Demo supports Stroops, so it should be able to handle XLM deposits with decimal amounts. But this has not been tested in the UI.
- **Not Audited**: The code has not undergone security audits.
- **Error Handling**: Error handling may not cover all edge cases.


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

See [Contributing](./CONTRIBUTING.md).

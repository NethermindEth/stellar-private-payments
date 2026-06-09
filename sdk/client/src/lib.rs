//! Stellar Private Payments SDK.
//!
//! Facade over the `sdk/` crates. Re-exports domain types, chain reads,
//! transaction builders, local storage, and proving behind a single crate.
//!
//! # Example
//!
//! ```no_run
//! use stellar_private_payments_sdk::{Client, ContractConfig};
//!
//! # async fn example(deployment: ContractConfig) -> anyhow::Result<()> {
//! let client = Client::new("https://soroban-testnet.stellar.org", deployment)?;
//! let state = client.all_contracts_data().await?;
//! println!("pools: {}", state.pools.len());
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]

pub use types::*;

pub mod chain {
    //! Stellar RPC client, indexer, and contract state reads.
    pub use stellar::{
        ContractDataStorage, Indexer, OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher,
        hash_ext_data_offchain,
    };
}

pub mod tx {
    //! Deposit / withdraw / transfer / transact builders and crypto helpers.
    pub use prover::{
        crypto, encryption, flows,
        flows::{TransactArtifacts, deposit, transact, transfer, withdraw},
        merkle, notes,
        prover::convert_proof_to_soroban,
        sparse_merkle,
    };
}

pub mod storage {
    //! SQLite-backed local state (events, notes, keys).
    pub use state::{
        AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, process_events, process_notes,
    };
}

pub mod proving {
    //! Groth16 proving and Circom witness generation.
    pub use prover::prover::Prover;
    pub use witness::WitnessCalculator;
}

pub mod plan;

pub use plan::{
    CombinationResult, PlanError, PlannedStep, SpendableNote, StepAction, StepNote,
    TRANSACTION_LIMIT, TransactionPlan, find_combination, plan,
};

mod client;

pub use client::Client;

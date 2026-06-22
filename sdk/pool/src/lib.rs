//! Stellar Private Payments SDK.
//!
//! Facade over the `sdk/` crates. Re-exports domain types, chain reads,
//! transaction builders, local storage, and proving behind a single crate.
//!
//! # Example
//!
//! ```no_run
//! use stellar_private_payments_sdk::{Client, types::ContractConfig};
//!
//! # async fn example(deployment: ContractConfig) -> anyhow::Result<()> {
//! let client = Client::new("https://soroban-testnet.stellar.org", deployment)?;
//! let state = client.all_contracts_data().await?;
//! println!("pools: {}", state.pools.len());
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]

pub mod types;

pub mod chain {
    //! Stellar RPC client, indexer, and contract state reads.
    pub use stellar::{
        Client, ContractDataStorage, Indexer, OnchainProofPublicInputs, PoolTransactInput,
        PreparedSorobanTx, RpcError, StateFetcher, hash_ext_data_offchain,
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
        AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, StoredUserKeys,
        process_events, process_notes,
    };
}

pub mod proving {
    //! Groth16 proving and Circom witness generation.
    pub use prover::prover::Prover;
    pub use witness::WitnessCalculator;
}

mod client;
mod error;
mod pool;

pub use client::Client;
pub use error::PoolError;
pub use pool::PrivatePool;
pub use types::{
    Estimate, PreparedTransaction, PrivatePoolConfig, SignedTransaction, SyncResult,
    TransactRequest, TransactionResult, TransferRecipient,
};

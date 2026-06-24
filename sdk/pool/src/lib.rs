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

    /// Synchronous RPC client, indexer, and state reads (native only).
    #[cfg(not(target_arch = "wasm32"))]
    pub mod blocking {
        pub use crate::indexer::Indexer;
        pub use stellar::blocking::{Client, StateFetcher};
    }
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

pub mod proving {
    //! Groth16 proving and Circom witness generation.
    pub use prover::prover::Prover;
    pub use witness::WitnessCalculator;
}

pub mod state {
    //! SQLite-backed local wallet and indexer state.
    pub use ::state::{
        AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, StoredUserKeys,
        process_events, process_notes,
    };
}

mod client;
mod error;
#[cfg(not(target_arch = "wasm32"))]
mod indexer;
mod plan;
mod pool;
mod prover;
mod transact;

pub use client::Client;
pub use error::PoolError;
pub use plan::PreparedTransactionPlan;
pub use pool::PrivatePool;
pub use prover::ProverEngine;
pub use transact::{
    BuildTransactParams, PreparedProverTx, PreparedTxPublic, TransactRequest,
    build_transact_params, build_validated_pool_tree, load_user_key_material,
    transact_request_from_step,
};
pub use types::{
    Estimate, PrivatePoolConfig, ProverArtifacts, SignedTransaction, SyncResult,
    TransactChainContext, TransactionResult, TransferRecipient,
};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = PreparedProverTx;

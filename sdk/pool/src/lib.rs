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
        Client, ContractDataStorage, Indexer, Limits, LocalSigner, OnchainProofPublicInputs,
        PoolTransactInput, PreparedSorobanTx, ReadXdr, RpcError, Signature, StateFetcher,
        TransactionEnvelope, TxConfirmStatus, auth_sign_steps, confirm_tx, hash_ext_data_offchain,
        submit_tx, unsigned_tx_for_signing, verify_tx,
    };

    /// Synchronous RPC client, indexer, and state reads (native only).
    #[cfg(not(target_arch = "wasm32"))]
    pub mod blocking {
        pub use crate::blocking::Indexer;
        pub use stellar::blocking::{Client, StateFetcher, confirm_tx, submit_tx};
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
    pub use crate::core::process_local_state_batch;
    pub use ::state::{
        AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, StoredUserKeys,
        process_events, process_notes,
    };
}

#[cfg(not(target_arch = "wasm32"))]
pub mod blocking;
mod client;
mod core;
mod error;
mod plan;
mod pool;
mod pool_storage;
mod prover;
mod signer;
mod transact;

pub use client::Client;
pub use core::PoolCore;
pub use error::PoolError;
pub use plan::PreparedTransactionPlan;
pub use pool::PrivatePool;
#[cfg(target_arch = "wasm32")]
pub use pool_storage::LocalPoolBackend;
#[cfg(not(target_arch = "wasm32"))]
pub use pool_storage::NativePoolBackend;
pub use pool_storage::PoolStorage;
pub use prover::ProverEngine;
#[cfg(not(target_arch = "wasm32"))]
pub use signer::LocalTransactionSigner;
pub use signer::TransactionSigner;
pub use transact::{
    BuildTransactParams, PreparedProverTx, PreparedTxPublic, TransactRequest,
    build_transact_params, build_validated_pool_tree, load_user_key_material,
    transact_request_from_step,
};
pub use tx_planner::SpendableNote;
pub use types::{
    Estimate, PoolChainConfig, PrivatePoolConfig, ProverArtifacts, SignedTransaction, SyncResult,
    TransactChainContext, TransactionResult, TransferRecipient,
};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = PreparedProverTx;

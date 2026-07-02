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
        TransactionEnvelope, TxConfirmStatus, WriteXdr, auth_sign_steps, confirm_tx,
        hash_ext_data_offchain, submit_tx, unsigned_tx_for_signing, verify_tx,
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

pub mod proving {
    //! Groth16 proving and Circom witness generation.
    pub use prover::prover::Prover;
    pub use witness::WitnessCalculator;
}

pub mod disclosure;

pub mod state {
    //! SQLite-backed local wallet and indexer state.
    pub use crate::core::process_local_state_batch;
    pub use ::state::{
        APP_SETTING_BOOTNODE_CONFIG, APP_SETTING_EXPLORER, AccountKeys,
        CURRENT_DISCLAIMER_HASH_HEX, CURRENT_DISCLAIMER_TEXT_MD, DerivedUserNoteRow,
        PoolCommitmentRow, SqliteStorage, StoredUserKeys, process_events, process_notes,
    };
}

#[cfg(not(target_arch = "wasm32"))]
pub mod blocking;
mod client;
mod core;
mod error;
mod plan;
mod pool;
mod prover;
mod signer;
mod sleep;
mod storage;
mod transact;

pub use client::Client;
pub use core::PoolCore;
pub use disclosure::{
    BuildDisclosureInputs, DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams,
    DisclosureRequest, build_disclosure_inputs, verify_disclosure_receipt,
};
pub use error::PoolError;
pub use plan::PreparedTransactionPlan;
pub use pool::PrivatePool;
pub use prover::{LocalProver, Prover, ProverEngine};
pub use signer::{LocalSigner, Signer};
pub use storage::{LocalStorage, Storage};
pub use transact::{
    BuildTransactParams, PreparedProverTx, PreparedTxPublic, TransactRequest,
    build_transact_params, build_validated_pool_tree, load_user_key_material,
    transact_request_from_step,
};
pub use tx_planner::{SpendTarget, SpendableNote, Transact};
pub use types::{
    Estimate, PoolChainConfig, PrivatePoolConfig, ProverArtifacts, SignedTransaction,
    TransactChainContext, TransactionResult, TransferRecipient,
};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = PreparedProverTx;

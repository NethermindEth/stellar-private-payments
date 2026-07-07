//! Stellar Private Payments SDK
//!
//! The main entry point is [`PrivatePool`], one
//! session per pool contract and Stellar account (deposit, transfer, withdraw,
//! transact, disclose).
//!
//! # Example
//!
//! ```no_run
//! use stellar_private_payments_sdk::{
//!     LocalProver, LocalSigner, LocalStorage, PrivatePool, PrivatePoolConfig, ProverArtifacts,
//!     SyncMode,
//!     types::{
//!         ContractConfig, EncryptionPublicKey, NoteAmount, NotePublicKey, TransferRecipient,
//!     },
//! };
//!
//! # async fn example(deployment: ContractConfig) -> Result<(), Box<dyn std::error::Error>> {
//! let storage_path = "wallet.sqlite";
//! let artifacts = ProverArtifacts::empty(); // load real circuit bytes before deposit
//!
//! let config = PrivatePoolConfig {
//!     rpc_url: "https://soroban-testnet.stellar.org".into(),
//!     contract_config: deployment,
//!     pool_contract_id: "CA2TZ...".into(),
//!     user_address: "G...".into(),
//!     storage_path: storage_path.into(),
//!     prover_artifacts: artifacts.clone(),
//! };
//!
//! let pool = PrivatePool::init(
//!     config,
//!     LocalStorage::open(storage_path)?,
//!     Box::new(LocalSigner::new(
//!         "S...",
//!         "Test SDF Network ; September 2015",
//!         "G...",
//!     )?),
//!     Box::new(LocalProver::from_artifacts(&artifacts)?),
//!     SyncMode::Inline,
//! )?;
//!
//! pool.deposit(10_000_000u128.into()).await?;
//!
//! let recipient = "G...";
//! pool.transfer(recipient, 5_000_000u128.into()).await?;
//! pool.withdraw(3_000_000u128.into(), "G...").await?;
//!
//! let balance = pool.balance().await?;
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
mod core;
mod error;
mod plan;
mod pool;
mod prover;
mod signer;
mod sleep;
mod storage;
mod transact;

pub use core::PoolCore;
pub use disclosure::{
    BuildDisclosureInputs, DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams,
    DisclosureRequest, build_disclosure_inputs, verify_disclosure_receipt,
};
pub use error::PoolError;
pub use plan::PreparedTransactionPlan;
pub use pool::{PrivatePool, SyncMode};
pub use prover::{LocalProver, NoopProver, Prover, ProverEngine};
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

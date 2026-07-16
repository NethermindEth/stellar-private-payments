//! Stellar Private Payments SDK
//!
//! Entry point: [`Client`] → [`Account`] → [`PrivatePool`].
//!
//! # Example
//!
//! ```no_run
//! use stellar_private_payments_sdk::{
//!     Client, Handle, LocalProver, LocalSigner, LocalStorage, ProverArtifacts, SyncMode,
//!     types::{ContractConfig, NoteAmount, PolicyFlags, TransferRecipient},
//! };
//!
//! # async fn example(deployment: ContractConfig) -> Result<(), Box<dyn std::error::Error>> {
//! let storage = LocalStorage::open("wallet.sqlite")?;
//! let artifacts = ProverArtifacts::empty(); // load real circuit bytes before deposit
//! let prover = Handle::from_box(
//!     Box::new(LocalProver::from_artifacts(&[(PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST, artifacts)])?)
//!         as Box<dyn stellar_private_payments_sdk::Prover>,
//! );
//! let signer = Handle::from_box(
//!     Box::new(LocalSigner::new("S...", "Test SDF Network ; September 2015", "G...")?)
//!         as Box<dyn stellar_private_payments_sdk::Signer>,
//! );
//!
//! let client = Client::init(
//!     "https://soroban-testnet.stellar.org",
//!     storage,
//!     prover,
//!     SyncMode::Inline,
//!     deployment,
//! )?;
//! let account = client.account("G...", signer)?;
//! let pool = account.pool("CA2TZ...")?;
//!
//! pool.deposit(10_000_000u128.into()).await?;
//! pool.transfer("G...", 5_000_000u128.into()).await?;
//! pool.withdraw(3_000_000u128.into(), "G...").await?;
//! let balance = pool.balance().await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]

pub mod types;

pub mod chain {
    //! Stellar RPC client, indexer, and contract state reads.
    pub use stellar::{
        Client as RpcClient, ContractDataStorage, Indexer, Limits, LocalSigner,
        OnchainProofPublicInputs, PoolTransactInput, PreparedSorobanTx, ReadXdr, RpcError,
        Signature, StateFetcher, TransactionEnvelope, TxConfirmStatus, WriteXdr, auth_sign_steps,
        confirm_tx, hash_ext_data_offchain, submit_tx, unsigned_tx_for_signing, verify_tx,
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

mod account;
#[cfg(not(target_arch = "wasm32"))]
pub mod blocking;
mod client;
mod core;
mod error;
mod handle;
mod plan;
mod pool;
mod prover;
mod signer;
mod sleep;
mod storage;
mod sync;
mod transact;

pub use account::Account;
pub use client::Client;
pub use core::PoolCore;
pub use disclosure::{
    BuildDisclosureInputs, DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams,
    DisclosureRequest, build_disclosure_inputs, verify_disclosure_receipt,
};
pub use error::Error;
pub use handle::Handle;
pub use plan::PreparedTransactionPlan;
pub use pool::PrivatePool;
pub use prover::{LocalProver, NoopProver, Prover, ProverEngine};
pub use signer::{LocalSigner, Signer};
pub use storage::{LocalStorage, Storage};
pub use sync::SyncMode;
pub use transact::{
    BuildTransactParams, PreparedProverTx, PreparedTxPublic, TransactRequest,
    build_transact_params, build_validated_pool_tree, load_user_key_material,
    transact_request_from_step,
};
pub use tx::encryption::KEY_DERIVATION_MESSAGE;
pub use tx_planner::{SpendTarget, SpendableNote, Transact};
pub use types::{
    Estimate, OperationalFeedItem, PolicyFlags, PortfolioBalance, PrivatePoolConfig,
    ProverArtifacts, RecipientLookup, SignedTransaction, TransactChainContext, TransactionResult,
    TransferRecipient, UserNoteSummary,
};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = PreparedProverTx;

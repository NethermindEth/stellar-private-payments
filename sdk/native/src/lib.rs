//! Stellar Private Payments SDK
//!
//! Entry point: [`Client`] → [`Account`] → [`PrivatePool`].
//!
//! # Example
//!
//! ```no_run
//! use stellar_private_payments::{
//!     CircuitStore, Client, Handle, LocalProver, LocalSigner, LocalStorage, Prover,
//!     types::{CircuitStem, ContractConfig, PolicyFlags},
//! };
//!
//! # async fn example(deployment: ContractConfig) -> Result<(), Box<dyn std::error::Error>> {
//! let storage = LocalStorage::open("wallet.sqlite")?;
//!
//! let store = CircuitStore::open("./circuits");
//! store.ensure_blocking()?;
//! let stem = CircuitStem::transact(
//!     PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
//!     Default::default(),
//! );
//! let artifacts = store.artifacts(&stem.to_string())?;
//! let prover = Handle::from_box(
//!     Box::new(LocalProver::from_artifacts(&[(stem, artifacts)])?) as Box<dyn Prover>,
//! );
//! let signer = Handle::from_box(
//!     Box::new(LocalSigner::new("S...", "Test SDF Network ; September 2015", "G...")?)
//!         as Box<dyn stellar_private_payments::Signer>,
//! );
//!
//! let client = Client::init(
//!     "https://soroban-testnet.stellar.org",
//!     storage,
//!     prover,
//!     deployment,
//!     None,
//! )?;
//! let account = client.account("G...", signer)?;
//! let pool = account.pool("CA2TZ...")?;
//!
//! pool.deposit(10_000_000u128.into()).await?;
//! let balance = pool.balance().await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]

pub mod chain;
pub mod circuits;
pub mod disclosure;
pub mod gvk;
pub mod planner;
pub mod state;
pub mod types;
pub mod zk;

mod account;
#[cfg(not(target_arch = "wasm32"))]
pub mod blocking;
mod client;
mod core;
mod correlation;
pub mod crypto;
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
#[cfg(not(target_arch = "wasm32"))]
pub use circuits::CircuitStore;
pub use circuits::{
    ArtifactKind, CIRCUITS_JSON, CircuitLockfile, artifact_file_name, artifact_sha256_bytes,
    circuit_hashes, circuit_lock, sha256_hex, verify_artifact_bytes,
};
pub use client::Client;
pub use core::PoolCore;
pub use disclosure::{
    BuildDisclosureInputs, DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams,
    DisclosureRequest, build_disclosure_inputs, verify_disclosure_receipt,
};
pub use error::{Error, PlanExecutionError};
pub use gvk::{GvkAudit, GvkTxAudit, audit_commitment_event, audit_nullifier_event};
pub use handle::Handle;
pub use plan::PreparedTransactionPlan;
pub use planner::{SpendTarget, SpendableNote, Transact};
pub use pool::PrivatePool;
pub use prover::{LocalProver, NoopProver, Prover, ProverEngine};
pub use signer::{LocalSigner, Signer};
pub use storage::{LocalStorage, Storage};
pub use sync::{BackgroundSync, BackgroundSyncStop, SyncHandle, SyncMode, bootnode_required};
pub use transact::{
    BuildTransactParams, PreparedProverTx, PreparedTxPublic, TransactRequest,
    build_transact_params, build_validated_pool_tree, load_user_key_material,
    transact_request_from_step,
};
pub use types::{
    Estimate, OperationalFeedItem, PolicyFlags, PortfolioBalance, PrivatePoolConfig,
    ProverArtifacts, RecipientLookup, SignedTransaction, TransactChainContext, TransactionResult,
    TransferRecipient, UserNoteSummary,
};
pub use zk::{
    encryption::KEY_DERIVATION_MESSAGE,
    gvk::{GvkAuditedNote, GvkRecoveredNote},
    prover::convert_proof_to_soroban,
};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = PreparedProverTx;

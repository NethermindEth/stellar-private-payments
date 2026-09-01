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
//! let artifacts = store.transact_artifacts()?;
//! let prover = Handle::from_box(
//!     Box::new(LocalProver::from_artifacts(&artifacts)?) as Box<dyn Prover>,
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
pub mod plan;
pub mod planner;
pub mod prover;
pub mod state;
pub mod transact;
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
mod pool;
mod signer;
mod sleep;
mod storage;
mod sync;

pub use account::Account;
#[cfg(not(target_arch = "wasm32"))]
pub use circuits::CircuitStore;
pub use circuits::{CIRCUITS_JSON, CircuitLockfile, circuit_lock};
pub use client::Client;
pub use error::{Error, PlanExecutionError};
pub use handle::Handle;
pub use pool::PrivatePool;
pub use prover::{LocalProver, Prover};
pub use signer::{LocalSigner, Signer};
pub use storage::{LocalStorage, Storage};
pub use sync::{BackgroundSync, BackgroundSyncStop, SyncMode, bootnode_required};

/// Groth16 prove output for a transact step (simulate / sign / submit).
pub type PreparedTransaction = transact::PreparedProverTx;

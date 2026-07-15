//! Transaction signing for async [`crate::pool::PrivatePool`] operations.

use stellar::PreparedSorobanTx;

use crate::{PreparedTransaction, error::Error, types::SignedTransaction};

mod local;

pub use local::LocalSigner;

/// Signs a simulated [`PreparedTransaction`] before chain submission.
#[async_trait::async_trait(?Send)]
pub trait Signer {
    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error>;

    /// Signs a prepared Soroban transaction (e.g. public-key registry
    /// `register`).
    async fn sign_soroban_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<SignedTransaction, Error> {
        let _ = prepared;
        Err(Error::Other(
            "signer does not support soroban transactions".into(),
        ))
    }
}

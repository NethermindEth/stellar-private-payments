//! Transaction signing for async [`crate::pool::PrivatePool`] operations.

use crate::{PreparedTransaction, error::PoolError, types::SignedTransaction};

#[cfg(not(target_arch = "wasm32"))]
mod local;

#[cfg(not(target_arch = "wasm32"))]
pub use local::LocalSigner;

/// Signs a simulated [`PreparedTransaction`] before chain submission.
#[async_trait::async_trait(?Send)]
pub trait Signer {
    async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, PoolError>;
}

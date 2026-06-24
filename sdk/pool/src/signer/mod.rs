//! Transaction signing for async [`crate::pool::PrivatePool`] operations.

use crate::{
    PreparedTransaction,
    error::PoolError,
    types::{PrivatePoolConfig, SignedTransaction},
};

#[cfg(not(target_arch = "wasm32"))]
mod local;

#[cfg(not(target_arch = "wasm32"))]
pub use local::LocalTransactionSigner;

/// Signs a simulated [`PreparedTransaction`] before chain submission.
#[async_trait::async_trait(?Send)]
pub trait TransactionSigner {
    async fn sign(
        &self,
        prepared: &PreparedTransaction,
        config: &PrivatePoolConfig,
    ) -> Result<SignedTransaction, PoolError>;
}

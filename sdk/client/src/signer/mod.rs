//! Transaction signing for async [`crate::pool::PrivatePool`] operations.

use crate::{PreparedTransaction, error::Error, types::SignedTransaction};

mod local;

pub use local::LocalSigner;

/// Signs a simulated [`PreparedTransaction`] before chain submission.
#[async_trait::async_trait(?Send)]
pub trait Signer {
    async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, Error>;
}

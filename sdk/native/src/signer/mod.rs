//! Transaction signing for async [`crate::pool::PrivatePool`] operations.

use crate::chain::PreparedSorobanTx;

use crate::{
    PreparedTransaction,
    error::Error,
    types::{KeyDerivationSignature, SignedTransaction, SignerAddress},
};

mod local;

pub use local::LocalSigner;

/// Signs a simulated [`PreparedTransaction`] before chain submission.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait Signer {
    fn signer_address(&self) -> SignerAddress;

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
        Err(Error::Other(anyhow::anyhow!(
            "signer does not support soroban transactions"
        )))
    }

    /// SEP-53 signature of `message`.
    async fn sign_message(&self, message: &str) -> Result<KeyDerivationSignature, Error> {
        let _ = message;
        Err(Error::Other(anyhow::anyhow!(
            "signer does not support message signing"
        )))
    }
}

#[cfg(target_arch = "wasm32")]
pub type SignerHandle = crate::Handle<dyn Signer>;
#[cfg(not(target_arch = "wasm32"))]
pub type SignerHandle = crate::Handle<dyn Signer + Send + Sync>;

#[cfg(target_arch = "wasm32")]
impl<T: Signer + 'static> From<T> for SignerHandle {
    fn from(value: T) -> Self {
        crate::Handle::from_box(Box::new(value) as Box<dyn Signer>)
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Signer + Send + Sync + 'static> From<T> for SignerHandle {
    fn from(value: T) -> Self {
        crate::Handle::from_box(Box::new(value) as Box<dyn Signer + Send + Sync>)
    }
}

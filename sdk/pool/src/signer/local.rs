use stellar::{Limits, LocalSigner as StellarSigner, TransactionEnvelope, WriteXdr};

use super::Signer;
use crate::{
    PreparedTransaction,
    error::PoolError,
    types::{PrivatePoolConfig, SignedTransaction},
};

/// In-process Ed25519 signer for native CLI and tests.
pub struct LocalSigner {
    stellar: StellarSigner,
    network_passphrase: String,
}

impl LocalSigner {
    pub fn new(secret_key: &str, network_passphrase: impl Into<String>) -> Result<Self, PoolError> {
        Ok(Self {
            stellar: StellarSigner::from_secret(secret_key)
                .map_err(|e| PoolError::Other(format!("signer: {e:#}")))?,
            network_passphrase: network_passphrase.into(),
        })
    }

    pub fn stellar_signer(&self) -> &StellarSigner {
        &self.stellar
    }

    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Deterministic signer for native tests.
    pub fn test_fixture(network_passphrase: impl Into<String>) -> Result<Self, PoolError> {
        Ok(Self {
            stellar: StellarSigner::test_fixture()
                .map_err(|e| PoolError::Other(format!("test signer: {e:#}")))?,
            network_passphrase: network_passphrase.into(),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for LocalSigner {
    async fn sign(
        &self,
        prepared: &PreparedTransaction,
        config: &PrivatePoolConfig,
    ) -> Result<SignedTransaction, PoolError> {
        let envelope = self
            .stellar
            .sign_prepared_transaction(
                &prepared.soroban_tx,
                &self.network_passphrase,
                &config.user_address,
            )
            .map_err(|e| PoolError::Other(format!("sign transaction: {e:#}")))?;
        signed_transaction_from_envelope(envelope)
    }
}

fn signed_transaction_from_envelope(
    envelope: TransactionEnvelope,
) -> Result<SignedTransaction, PoolError> {
    let signed_xdr = envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| PoolError::Other(format!("encode signed transaction xdr: {e}")))?;
    Ok(SignedTransaction { signed_xdr })
}

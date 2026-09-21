use anyhow::Context;

use crate::chain::{Limits, LocalSigner as StellarSigner, PreparedSorobanTx, WriteXdr};

use super::Signer;
use crate::{
    PreparedTransaction,
    error::Error,
    types::{SignedTransaction, SignerAddress},
};

/// In-process Ed25519 signer for native CLI and tests.
pub struct LocalSigner {
    stellar: StellarSigner,
    network_passphrase: String,
    signer_address: SignerAddress,
}

impl LocalSigner {
    pub fn new(
        secret_key: &str,
        network_passphrase: impl Into<String>,
        signer_address: SignerAddress,
    ) -> Result<Self, Error> {
        Ok(Self {
            stellar: StellarSigner::from_secret(secret_key).context("signer")?,
            network_passphrase: network_passphrase.into(),
            signer_address,
        })
    }

    pub fn stellar_signer(&self) -> &StellarSigner {
        &self.stellar
    }

    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    pub fn signer_address(&self) -> &SignerAddress {
        &self.signer_address
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for LocalSigner {
    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error> {
        self.sign_soroban_transaction(&prepared.soroban_tx).await
    }

    async fn sign_soroban_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<SignedTransaction, Error> {
        let envelope = self
            .stellar
            .sign_prepared_transaction(prepared, &self.network_passphrase, &self.signer_address)
            .context("sign transaction")?;
        let signed_xdr = envelope
            .to_xdr_base64(Limits::none())
            .context("encode signed transaction xdr")?;
        Ok(SignedTransaction { signed_xdr })
    }
}

//! Transaction signer backed by a `stellar keys` alias.
//!
//! Pool transacts delegate signing to `stellar tx sign --sign-with-key`, so
//! keys in the OS secure store work without exporting secrets into this
//! process.

use std::path::PathBuf;

use stellar_private_payments_sdk::{
    Error, PreparedTransaction, Signer,
    chain::{Limits, PreparedSorobanTx, ReadXdr, TransactionEnvelope, WriteXdr},
    types::SignedTransaction,
};

use crate::stellar_cli;

/// Signs pool transactions using an alias resolved through the Stellar CLI.
pub struct AliasSigner {
    pub alias: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub config_dir: Option<PathBuf>,
}

impl AliasSigner {
    pub fn sign_prepared_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<TransactionEnvelope, Error> {
        let signed_xdr = stellar_cli::sign_tx(
            &self.alias,
            &prepared.tx_xdr,
            &self.rpc_url,
            &self.network_passphrase,
            self.config_dir.as_deref(),
        )
        .map_err(|e| {
            Error::Other(format!(
                "sign transaction for alias `{}`: {e:#}",
                self.alias
            ))
        })?;
        TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none())
            .map_err(|e| Error::Other(format!("decode signed transaction xdr: {e}")))
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for AliasSigner {
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
        let envelope = self.sign_prepared_transaction(prepared)?;
        let signed_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| Error::Other(format!("encode signed transaction xdr: {e}")))?;
        Ok(SignedTransaction { signed_xdr })
    }
}

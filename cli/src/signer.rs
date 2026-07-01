//! Transaction signer backed by a `stellar keys` alias.
//!
//! The pool's `transact` call requires Soroban authorization-entry signatures,
//! which the `stellar` binary cannot produce on its own. So we keep the SDK's
//! in-process signing (`LocalSigner`) but source the secret from the alias via
//! `stellar keys secret` **only when a transaction is actually signed** — read
//! operations (balance, notes) never trigger this.

use std::path::PathBuf;

use stellar_private_payments_sdk::{
    LocalSigner, PoolError, PreparedTransaction, Signer, types::SignedTransaction,
};

use crate::stellar_cli;

/// Signs pool transactions using an alias resolved through the Stellar CLI.
pub struct AliasSigner {
    pub alias: String,
    pub network_passphrase: String,
    pub user_address: String,
    pub config_dir: Option<PathBuf>,
}

#[async_trait::async_trait(?Send)]
impl Signer for AliasSigner {
    async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, PoolError> {
        let secret = stellar_cli::secret(&self.alias, self.config_dir.as_deref())
            .map_err(|e| PoolError::Other(format!("fetch secret for alias `{}`: {e:#}", self.alias)))?;
        let inner = LocalSigner::new(
            &secret,
            self.network_passphrase.clone(),
            self.user_address.clone(),
        )?;
        inner.sign(prepared).await
    }
}

//! Sync wrapper around [`crate::Account`] via a shared Tokio runtime.

use types::{EncryptionPublicKey, Field, NotePublicKey, PortfolioBalance, UserNoteSummary};

use crate::{
    Error, Handle, Signer, account::Account as AsyncAccount, storage::LocalStorage,
    types::TransactionResult,
};

use super::{pool::PrivatePool, runtime::block_on};

/// Stellar account session (address + signer) with blocking pool factory.
///
/// Construct via [`super::Client::account`].
pub struct Account {
    inner: AsyncAccount<LocalStorage>,
}

impl Account {
    pub(crate) fn from_inner(inner: AsyncAccount<LocalStorage>) -> Self {
        Self { inner }
    }

    pub fn user_address(&self) -> &str {
        self.inner.user_address()
    }

    pub fn signer(&self) -> &Handle<dyn Signer> {
        self.inner.signer()
    }

    pub fn storage(&self) -> &LocalStorage {
        self.inner.storage()
    }

    /// Catch local storage up to the current chain tip for the deployment.
    pub fn sync(&self) -> Result<(), Error> {
        block_on(self.inner.sync())
    }

    pub fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        block_on(self.inner.portfolio())
    }

    pub fn user_public_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        block_on(self.inner.user_public_keys())
    }

    pub fn asp_secret(&self) -> Result<Field, Error> {
        block_on(self.inner.asp_secret())
    }

    pub fn derive_asp_user_leaf(
        &self,
        note_public_key: Option<NotePublicKey>,
        membership_blinding: Option<Field>,
    ) -> Result<Field, Error> {
        block_on(
            self.inner
                .derive_asp_user_leaf(note_public_key, membership_blinding),
        )
    }

    pub fn user_notes(&self, limit: u32) -> Result<Vec<UserNoteSummary>, Error> {
        block_on(self.inner.user_notes(limit))
    }

    pub fn is_registered(&self) -> Result<bool, Error> {
        block_on(self.inner.is_registered())
    }

    /// Register this account's public keys on the deployment-wide registry.
    ///
    /// When both key arguments are `None`, loads the keys from local storage.
    pub fn register_public_keys(
        &self,
        note_public_key: Option<NotePublicKey>,
        encryption_public_key: Option<EncryptionPublicKey>,
    ) -> Result<TransactionResult, Error> {
        block_on(
            self.inner
                .register_public_keys(note_public_key, encryption_public_key),
        )
    }

    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool, Error> {
        Ok(PrivatePool::from_inner(self.inner.pool(pool_contract_id)?))
    }
}

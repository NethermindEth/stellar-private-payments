//! Sync wrapper around [`crate::Account`] via a shared Tokio runtime.

use types::PortfolioBalance;

use crate::{Error, Handle, Signer, account::Account as AsyncAccount, storage::LocalStorage};

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

    pub fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        block_on(self.inner.portfolio())
    }

    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool, Error> {
        Ok(PrivatePool::from_inner(self.inner.pool(pool_contract_id)?))
    }
}

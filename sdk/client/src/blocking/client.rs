//! Sync wrapper around [`crate::Client`] via a shared Tokio runtime.

use types::{ContractConfig, OperationalFeedItem, RecipientLookup};

use crate::{
    Error, Handle, Prover, Signer, SyncMode, chain::StateFetcher, client::Client as AsyncClient,
    storage::LocalStorage,
};

use super::{account::Account, runtime::block_on};

/// Blocking wrapper around [`crate::Client`].
pub struct Client {
    inner: AsyncClient<LocalStorage>,
}

impl Client {
    pub fn init(
        rpc_url: impl AsRef<str>,
        storage: LocalStorage,
        prover: Handle<dyn Prover>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncClient::init(rpc_url, storage, prover, sync_mode, contract_config)?,
        })
    }

    /// Read-only client with a no-op prover (balance, notes, sync, portfolio).
    pub fn init_readonly(
        rpc_url: impl AsRef<str>,
        storage: LocalStorage,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncClient::init_readonly(rpc_url, storage, sync_mode, contract_config)?,
        })
    }

    pub fn storage(&self) -> &LocalStorage {
        self.inner.storage()
    }

    pub fn prover(&self) -> &Handle<dyn Prover> {
        self.inner.prover()
    }

    pub fn contract_config(&self) -> &ContractConfig {
        self.inner.contract_config()
    }

    pub fn sync(&self) -> Result<(), Error> {
        block_on(self.inner.sync())
    }

    pub fn operational_feed(&self, limit: u32) -> Result<Vec<OperationalFeedItem>, Error> {
        block_on(self.inner.operational_feed(limit))
    }

    pub fn recipient_lookup(&self, address: impl AsRef<str>) -> Result<RecipientLookup, Error> {
        block_on(self.inner.recipient_lookup(address))
    }

    pub fn account(
        &self,
        user_address: impl Into<String>,
        signer: Handle<dyn Signer>,
    ) -> Result<Account, Error> {
        Ok(Account::from_inner(
            self.inner.account(user_address, signer)?,
        ))
    }

    pub fn state_fetcher(&self) -> Result<StateFetcher, Error> {
        self.inner.state_fetcher()
    }
}

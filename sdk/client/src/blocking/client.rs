//! Sync wrapper around [`crate::Client`] via a shared Tokio runtime.

use types::{ContractConfig, OperationalFeedItem, RecipientLookup};

use crate::{
    BackgroundSync, Error, Handle, Prover, Signer, chain::StateFetcher,
    client::Client as AsyncClient, storage::LocalStorage,
};

use super::{account::Account, runtime::block_on};

/// Blocking wrapper around [`crate::Client`].
pub struct Client {
    inner: AsyncClient<LocalStorage>,
}

impl Client {
    #[tracing::instrument(name = "blocking_client_init", level = "info", skip_all, fields(correlation_id = %crate::correlation::correlation_id_or_new()))]
    pub fn init(
        rpc_url: impl AsRef<str>,
        storage: LocalStorage,
        prover: Handle<dyn Prover>,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncClient::init(rpc_url, storage, prover, contract_config, bootnode_url)?,
        })
    }

    /// Read-only client with a no-op prover (balance, notes, sync, portfolio).
    pub fn init_readonly(
        rpc_url: impl AsRef<str>,
        storage: LocalStorage,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncClient::init_readonly(rpc_url, storage, contract_config, bootnode_url)?,
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

    /// Switch to background sync mode and return an owned [`BackgroundSync`]
    /// task. Does not spawn — call [`BackgroundSync::run`] on an async runtime.
    pub fn background_sync(&mut self) -> Result<BackgroundSync<LocalStorage>, Error> {
        self.inner.background_sync()
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

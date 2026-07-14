//! Sync wrapper around [`crate::Client`] via a shared Tokio runtime.

use types::ContractConfig;

use crate::{
    Handle, PoolError, Prover, Signer, SyncMode, chain::StateFetcher,
    client::Client as AsyncClient, storage::LocalStorage,
};

use super::{account::Account, runtime::block_on};

/// Blocking wrapper around [`crate::Client`].
pub struct Client {
    inner: AsyncClient<LocalStorage>,
}

impl Client {
    pub fn new(
        storage: LocalStorage,
        prover: Handle<dyn Prover>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
        rpc_url: impl Into<String>,
    ) -> Self {
        Self {
            inner: AsyncClient::new(storage, prover, sync_mode, contract_config, rpc_url),
        }
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

    pub fn rpc_url(&self) -> &str {
        self.inner.rpc_url()
    }

    pub fn sync(&self) -> Result<(), PoolError> {
        block_on(self.inner.sync())
    }

    pub fn account(
        &self,
        user_address: impl Into<String>,
        signer: Handle<dyn Signer>,
    ) -> Result<Account, PoolError> {
        Ok(Account::from_inner(
            self.inner.account(user_address, signer)?,
        ))
    }

    pub fn state_fetcher(&self) -> Result<StateFetcher, PoolError> {
        self.inner.state_fetcher()
    }
}

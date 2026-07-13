//! Sync wrapper around [`crate::Client`] via a shared Tokio runtime.

use types::ContractConfig;

use crate::{
    Handle, PoolError, Prover, Signer, SyncMode, chain::StateFetcher,
    client::Client as AsyncClient, storage::LocalStorage,
};

use super::{account::Account, runtime::block_on};

/// Deployment-scoped sync SDK runtime: storage + prover, plus helpers to sync
/// and create account sessions.
pub struct Client {
    inner: AsyncClient<LocalStorage>,
}

impl Client {
    pub fn new(storage: LocalStorage, prover: Handle<dyn Prover>, sync_mode: SyncMode) -> Self {
        Self {
            inner: AsyncClient::new(storage, prover, sync_mode),
        }
    }

    pub fn storage(&self) -> &LocalStorage {
        self.inner.storage()
    }

    pub fn prover(&self) -> &Handle<dyn Prover> {
        self.inner.prover()
    }

    pub fn sync(&self, rpc_url: &str, contract_config: &ContractConfig) -> Result<(), PoolError> {
        block_on(self.inner.sync(rpc_url, contract_config))
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

    pub fn state_fetcher(
        &self,
        rpc_url: &str,
        contract_config: ContractConfig,
    ) -> Result<StateFetcher, PoolError> {
        self.inner.state_fetcher(rpc_url, contract_config)
    }
}

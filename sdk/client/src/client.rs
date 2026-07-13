use types::ContractConfig;

use crate::{
    Account, Handle, PoolError, Prover, Signer, Storage, SyncMode,
    chain::{Indexer, StateFetcher},
};

/// Deployment-scoped SDK runtime: storage + prover, plus helpers to sync and
/// create account sessions.
pub struct Client<S: Storage> {
    storage: S,
    prover: Handle<dyn Prover>,
    sync_mode: SyncMode,
}

impl<S: Storage> Client<S> {
    pub fn new(storage: S, prover: Handle<dyn Prover>, sync_mode: SyncMode) -> Self {
        Self {
            storage,
            prover,
            sync_mode,
        }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn prover(&self) -> &Handle<dyn Prover> {
        &self.prover
    }

    /// Catch local storage up to the current chain tip for the deployment
    pub async fn sync(
        &self,
        rpc_url: &str,
        contract_config: &ContractConfig,
    ) -> Result<(), PoolError> {
        let rpc = stellar::Client::new(rpc_url)
            .map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;
        let indexer = Indexer::init(rpc, self.storage.fork()?, contract_config)
            .await
            .map_err(|e| PoolError::Other(format!("indexer: {e:#}")))?;
        indexer
            .catch_up()
            .await
            .map_err(|e| PoolError::Other(format!("indexer catch-up: {e:#}")))?;
        self.storage.process_pending_state().await?;
        Ok(())
    }

    /// Create an [`Account`] session
    pub fn account(
        &self,
        user_address: impl Into<String>,
        signer: Handle<dyn Signer>,
    ) -> Result<Account<S>, PoolError> {
        Ok(Account::new(
            self.storage.fork()?,
            self.prover.clone(),
            user_address.into(),
            signer,
            self.sync_mode,
        ))
    }

    /// Chain-state accessor
    pub fn state_fetcher(
        &self,
        rpc_url: &str,
        contract_config: ContractConfig,
    ) -> Result<StateFetcher, PoolError> {
        StateFetcher::new(rpc_url, contract_config)
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))
    }
}

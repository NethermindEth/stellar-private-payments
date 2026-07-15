use types::ContractConfig;

use crate::{
    Account, Error, Handle, Prover, Signer, Storage, SyncMode,
    chain::{Indexer, StateFetcher},
};

/// Top-level SDK client for a privacy pools deployment.
///
/// Configure with local storage, a prover, and RPC; then sync and open
/// [`Account`] sessions.
pub struct Client<S: Storage> {
    storage: S,
    prover: Handle<dyn Prover>,
    sync_mode: SyncMode,
    contract_config: ContractConfig,
    rpc_url: String,
}

impl<S: Storage> Client<S> {
    pub fn new(
        storage: S,
        prover: Handle<dyn Prover>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
        rpc_url: impl Into<String>,
    ) -> Self {
        Self {
            storage,
            prover,
            sync_mode,
            contract_config,
            rpc_url: rpc_url.into(),
        }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn prover(&self) -> &Handle<dyn Prover> {
        &self.prover
    }

    pub fn contract_config(&self) -> &ContractConfig {
        &self.contract_config
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Catch local storage up to the current chain tip for the deployment.
    pub async fn sync(&self) -> Result<(), Error> {
        let rpc = stellar::Client::new(&self.rpc_url)
            .map_err(|e| Error::Other(format!("rpc client: {e:#}")))?;
        let indexer = Indexer::init(rpc, self.storage.fork()?, &self.contract_config)
            .await
            .map_err(|e| Error::Other(format!("indexer: {e:#}")))?;
        indexer
            .catch_up()
            .await
            .map_err(|e| Error::Other(format!("indexer catch-up: {e:#}")))?;
        self.storage.process_pending_state().await?;
        Ok(())
    }

    /// Create an [`Account`] session.
    pub fn account(
        &self,
        user_address: impl Into<String>,
        signer: Handle<dyn Signer>,
    ) -> Result<Account<S>, Error> {
        Ok(Account::new(
            self.storage.fork()?,
            self.prover.clone(),
            user_address.into(),
            signer,
            self.sync_mode,
            self.contract_config.clone(),
            self.rpc_url.clone(),
        ))
    }

    /// Chain-state accessor for this deployment.
    pub fn state_fetcher(&self) -> Result<StateFetcher, Error> {
        StateFetcher::new(&self.rpc_url, self.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))
    }
}

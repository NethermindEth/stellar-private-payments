use types::{ContractConfig, PortfolioBalance};

use crate::{
    Error, Handle, PrivatePool, PrivatePoolConfig, Prover, Signer, Storage, SyncMode,
    chain::Indexer,
};

/// Stellar account session
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: String,
    signer: Handle<dyn Signer>,
    sync_mode: SyncMode,
    contract_config: ContractConfig,
    rpc_url: String,
}

impl<S: Storage> Account<S> {
    pub(crate) fn new(
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: String,
        signer: Handle<dyn Signer>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
        rpc_url: String,
    ) -> Self {
        Self {
            storage,
            prover,
            user_address,
            signer,
            sync_mode,
            contract_config,
            rpc_url,
        }
    }

    pub fn user_address(&self) -> &str {
        &self.user_address
    }

    pub fn signer(&self) -> &Handle<dyn Signer> {
        &self.signer
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Portfolio balances across all enabled pools in the deployment.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_portfolio_balances(&self.user_address, &self.contract_config)
            .await
    }

    /// Create an owned pool session for `pool_contract_id`.
    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool<S>, Error> {
        let cfg = PrivatePoolConfig {
            rpc_url: self.rpc_url.clone(),
            contract_config: self.contract_config.clone(),
            pool_contract_id: pool_contract_id.into(),
            user_address: self.user_address.clone(),
        };

        PrivatePool::init(
            cfg,
            self.storage.fork()?,
            self.signer.clone(),
            self.prover.clone(),
            self.sync_mode,
        )
    }

    async fn ensure_synced(&self) -> Result<(), Error> {
        match self.sync_mode {
            SyncMode::Inline => self.sync().await?,
            SyncMode::Background => {}
        }
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
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
}

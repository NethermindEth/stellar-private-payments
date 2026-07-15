use types::{ContractConfig, OperationalFeedItem, RecipientLookup};

use crate::{
    Account, Error, Handle, NoopProver, Prover, Signer, Storage, SyncMode, chain::StateFetcher,
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

    /// Read-only client with a no-op prover (balance, notes, sync, portfolio).
    pub fn new_readonly(
        storage: S,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
        rpc_url: impl Into<String>,
    ) -> Self {
        Self::new(
            storage,
            Handle::from_box(Box::new(NoopProver) as Box<dyn Prover>),
            sync_mode,
            contract_config,
            rpc_url,
        )
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
        crate::sync::catch_up(&self.storage, &self.rpc_url, &self.contract_config).await
    }

    /// Recent deployment activity (pool events, registry registrations, ASP
    /// updates).
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn operational_feed(&self, limit: u32) -> Result<Vec<OperationalFeedItem>, Error> {
        self.ensure_synced().await?;
        self.storage
            .operational_feed(limit, &self.contract_config)
            .await
    }

    /// Look up a Stellar address in the on-chain public key registry index.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn recipient_lookup(
        &self,
        address: impl AsRef<str>,
    ) -> Result<RecipientLookup, Error> {
        self.ensure_synced().await?;
        self.storage
            .recipient_lookup(address.as_ref(), &self.contract_config)
            .await
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

    async fn ensure_synced(&self) -> Result<(), Error> {
        match self.sync_mode {
            SyncMode::Inline => self.sync().await?,
            SyncMode::Background => {}
        }
        Ok(())
    }
}

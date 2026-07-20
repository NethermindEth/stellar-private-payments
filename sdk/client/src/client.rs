use types::{ContractConfig, OperationalFeedItem, RecipientLookup};

use crate::{
    Account, Error, Handle, NoopProver, Prover, Signer, Storage, SyncMode,
    chain::{RpcClient, StateFetcher},
    sync::catch_up,
};

/// Top-level SDK client for a privacy pools deployment.
///
/// Configure with local storage, a prover, and RPC; then sync and open
/// [`Account`] sessions.
pub struct Client<S: Storage> {
    rpc: RpcClient,
    storage: S,
    prover: Handle<dyn Prover>,
    sync_mode: SyncMode,
    contract_config: ContractConfig,
}

impl<S: Storage> Client<S> {
    pub fn init(
        rpc_url: impl AsRef<str>,
        storage: S,
        prover: Handle<dyn Prover>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
    ) -> Result<Self, Error> {
        let rpc = RpcClient::new(rpc_url.as_ref())
            .map_err(|e| Error::Other(format!("rpc error: {e:#}")))?;
        Ok(Self {
            rpc,
            storage,
            prover,
            sync_mode,
            contract_config,
        })
    }

    /// Read-only client with a no-op prover (balance, notes, sync, portfolio).
    pub fn init_readonly(
        rpc_url: impl AsRef<str>,
        storage: S,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
    ) -> Result<Self, Error> {
        Self::init(
            rpc_url,
            storage,
            Handle::from_box(Box::new(NoopProver) as Box<dyn Prover>),
            sync_mode,
            contract_config,
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

    /// Shared Stellar RPC client (cheap to clone).
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Catch local storage up to the current chain tip for the deployment.
    pub async fn sync(&self) -> Result<(), Error> {
        catch_up(&self.rpc, &self.storage, &self.contract_config).await
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
            self.rpc.clone(),
            self.storage.fork()?,
            self.prover.clone(),
            user_address.into(),
            signer,
            self.sync_mode,
            self.contract_config.clone(),
        ))
    }

    /// Chain-state accessor for this deployment.
    pub fn state_fetcher(&self) -> Result<StateFetcher, Error> {
        StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
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

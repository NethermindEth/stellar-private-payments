//! Sync wrapper around [`crate::Client`] via a shared Tokio runtime.

use crate::types::{
    ContractConfig, Field, NoteKeyOwnerLookup, NoteOwnerAddress, OperationalFeedItem,
    RecipientLookup,
};

use crate::{
    BackgroundSync, Error, ProverHandle, SignerHandle, StorageHandle, chain::StateFetcher,
    client::Client as AsyncClient, storage::LocalStorage,
};

use super::{
    account::Account,
    operator::{AllowlistOperator, BlocklistOperator, GvkAuthority, PoolAdmin},
    runtime::block_on,
};

/// Blocking wrapper around [`crate::Client`].
pub struct Client {
    inner: AsyncClient,
}

impl Client {
    #[tracing::instrument(name = "blocking_client_init", level = "info", skip_all, fields(correlation_id = %crate::correlation::correlation_id_or_new()))]
    pub fn init(
        rpc_url: impl AsRef<str>,
        storage: LocalStorage,
        prover: ProverHandle,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
    ) -> Result<Self, Error> {
        let storage = StorageHandle::from(storage);
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
        let storage = StorageHandle::from(storage);
        Ok(Self {
            inner: AsyncClient::init_readonly(rpc_url, storage, contract_config, bootnode_url)?,
        })
    }

    pub fn storage(&self) -> &StorageHandle {
        self.inner.storage()
    }

    pub fn prover(&self) -> &ProverHandle {
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
    pub fn background_sync(&mut self) -> Result<BackgroundSync, Error> {
        self.inner.background_sync()
    }

    pub fn operational_feed(&self, limit: u32) -> Result<Vec<OperationalFeedItem>, Error> {
        block_on(self.inner.operational_feed(limit))
    }

    pub fn recipient_lookup(&self, address: impl AsRef<str>) -> Result<RecipientLookup, Error> {
        block_on(self.inner.recipient_lookup(address))
    }

    /// Blocking mirror of [`crate::Client::note_key_owner_lookup`].
    pub fn note_key_owner_lookup(&self, note_keys: &[Field]) -> Result<NoteKeyOwnerLookup, Error> {
        block_on(self.inner.note_key_owner_lookup(note_keys))
    }

    /// Blocking mirror of [`crate::Client::account`]; the same
    /// owner-must-equal-signer rule applies.
    pub fn account(
        &self,
        user_address: NoteOwnerAddress,
        signer: SignerHandle,
    ) -> Result<Account, Error> {
        Ok(Account::from_inner(
            self.inner.account(user_address, signer)?,
        ))
    }

    pub fn state_fetcher(&self) -> Result<StateFetcher, Error> {
        self.inner.state_fetcher()
    }

    /// Membership trees of the deployment, `asp_membership` first.
    pub fn allowlist_ids(&self) -> Vec<String> {
        self.inner.allowlist_ids()
    }

    /// Non-membership trees of the deployment.
    pub fn blocklist_ids(&self) -> Vec<String> {
        self.inner.blocklist_ids()
    }

    /// Pools of the deployment, enabled or not, in config order.
    pub fn pool_ids(&self) -> Vec<String> {
        self.inner.pool_ids()
    }

    /// Open an [`AllowlistOperator`] session for `contract_id`, listed in
    /// [`Self::allowlist_ids`] or not.
    pub fn allowlist_operator(&self, contract_id: &str) -> AllowlistOperator {
        AllowlistOperator::from_inner(self.inner.allowlist_operator(contract_id))
    }

    /// Open a [`BlocklistOperator`] session for `contract_id`, listed in
    /// [`Self::blocklist_ids`] or not.
    pub fn blocklist_operator(&self, contract_id: &str) -> BlocklistOperator {
        BlocklistOperator::from_inner(self.inner.blocklist_operator(contract_id))
    }

    /// Open a [`PoolAdmin`] session for `contract_id`, listed in
    /// [`Self::pool_ids`] or not.
    pub fn pool_admin(&self, contract_id: &str) -> PoolAdmin {
        PoolAdmin::from_inner(self.inner.pool_admin(contract_id))
    }

    /// Open a [`GvkAuthority`] session for a Global View Key private key.
    pub fn gvk_authority(&self, global_view_private_key: Field) -> Result<GvkAuthority, Error> {
        Ok(GvkAuthority::from_inner(
            self.inner.gvk_authority(global_view_private_key)?,
        ))
    }
}

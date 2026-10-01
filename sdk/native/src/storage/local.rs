use std::{collections::HashSet, path::PathBuf};

use futures::lock::{Mutex, MutexGuard};

use anyhow::Context;

use crate::{
    chain::ContractDataStorage,
    planner::SpendableNote,
    state::SqliteStorage,
    storage::NoteKeyPair,
    types::{
        ContractConfig, ContractsEventData, EncryptionKeyPair, EncryptionPublicKey, Field,
        GvkAuthoritySetting, NotePublicKey, OperationalFeedItem, PortfolioBalance,
        PortfolioPoolEntry, RecipientLookup, SyncMetadata, UserNoteSummary,
    },
    zk::flows::TransactParams,
};

use super::{
    Storage, map_build_params, map_private_keys, operational_feed_from_storage,
    pool_notes_from_storage, portfolio_balances_from_storage, recipient_lookup_from_storage,
    spendable_notes_from_storage, user_notes_from_storage,
};
use crate::{
    core::process_local_state,
    disclosure::{DisclosureInputs, DisclosureInputsRequest, map_build_disclosure_inputs},
    error::Error,
    transact::TransactRequest,
};

/// In-process SQLite wallet storage (native only).
pub struct LocalStorage {
    path: PathBuf,
    db: Mutex<SqliteStorage>,
}

impl LocalStorage {
    pub fn open(storage_path: &str) -> Result<Self, Error> {
        let path = PathBuf::from(storage_path);
        let db = futures::executor::block_on(SqliteStorage::connect_file(&path))
            .context("open storage")?;
        Ok(Self {
            path,
            db: Mutex::new(db),
        })
    }

    pub async fn storage(&self) -> MutexGuard<'_, SqliteStorage> {
        self.db.lock().await
    }

    pub async fn storage_mut(&self) -> MutexGuard<'_, SqliteStorage> {
        self.db.lock().await
    }

    pub async fn get_gvk_authority_setting(&self) -> Result<Option<GvkAuthoritySetting>, Error> {
        self.storage()
            .await
            .get_gvk_authority_setting()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("read GVK authority setting: {e:#}")))
    }

    pub async fn set_gvk_authority_setting(
        &self,
        setting: &GvkAuthoritySetting,
    ) -> Result<(), Error> {
        self.storage_mut()
            .await
            .set_gvk_authority_setting(setting)
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("write GVK authority setting: {e:#}")))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ContractDataStorage for LocalStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        self.storage().await.get_sync_metadata().await
    }

    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
        self.storage_mut().await.save_events_batch(&batch).await
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        self.storage_mut()
            .await
            .save_sync_progress(&metadata, fully_indexed)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Storage for LocalStorage {
    fn fork(&self) -> Result<crate::storage::StorageHandle, Error> {
        let db = futures::executor::block_on(SqliteStorage::connect_file(self.path.as_path()))
            .context("fork storage")?;
        let forked = Self {
            path: self.path.clone(),
            db: Mutex::new(db),
        };
        Ok(crate::storage::StorageHandle::from(forked))
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, Error> {
        spendable_notes_from_storage(&*self.storage().await, pool_contract_id, user_address).await
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        pool_notes_from_storage(&*self.storage().await, pool_contract_id, user_address).await
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        enabled_pools: &[PortfolioPoolEntry],
    ) -> Result<Vec<PortfolioBalance>, Error> {
        portfolio_balances_from_storage(&*self.storage().await, user_address, enabled_pools).await
    }

    async fn list_user_notes(
        &self,
        user_address: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        user_notes_from_storage(&*self.storage().await, user_address, limit).await
    }

    async fn operational_feed(
        &self,
        limit: u32,
        config: &ContractConfig,
    ) -> Result<Vec<OperationalFeedItem>, Error> {
        operational_feed_from_storage(&*self.storage().await, limit, config).await
    }

    async fn recipient_lookup(
        &self,
        address: &str,
        config: &ContractConfig,
    ) -> Result<RecipientLookup, Error> {
        recipient_lookup_from_storage(&*self.storage().await, address, config).await
    }

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error> {
        map_build_params(crate::transact::build_transact_params(&*self.storage().await, req).await)
    }

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error> {
        map_build_disclosure_inputs(
            crate::disclosure::build_disclosure_inputs(&*self.storage().await, req).await,
        )
    }

    async fn privacy_keys_exist(&self, user_address: &str) -> Result<bool, Error> {
        Ok(self
            .storage()
            .await
            .get_private_keys(user_address)
            .await
            .context("check stored private keys")?
            .is_some())
    }

    async fn save_private_keys(
        &self,
        user_address: &str,
        note_keypair: &NoteKeyPair,
        encryption_keypair: &EncryptionKeyPair,
        membership_blinding: &Field,
    ) -> Result<(), Error> {
        Ok(self
            .storage_mut()
            .await
            .save_encryption_and_note_keypairs(
                user_address,
                note_keypair,
                encryption_keypair,
                membership_blinding,
            )
            .await
            .context("save private keys")?)
    }

    async fn asp_secret(&self, user_address: &str) -> Result<Field, Error> {
        Ok(map_private_keys(&*self.storage().await, user_address)
            .await?
            .membership_blinding)
    }

    async fn privacy_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let keys = map_private_keys(&*self.storage().await, user_address).await?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }

    async fn registered_privacy_keys(
        &self,
        address: &str,
        _public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let entry = self
            .storage()
            .await
            .lookup_public_key_by_address(address)
            .await
            .context("lookup recipient")?
            .ok_or_else(|| {
                Error::Other(anyhow::anyhow!(
                    "recipient {address} not found in the public key registry; \
                     they must register keys on-chain"
                ))
            })?;
        Ok((entry.note_key, entry.encryption_key))
    }

    async fn process_pending_state(&self) -> Result<(), Error> {
        process_local_state(&mut *self.storage_mut().await).await
    }

    async fn clear_indexing_cursors(&self) -> Result<(), Error> {
        Ok(self.storage_mut().await.clear_indexing_cursors().await?)
    }

    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error> {
        Ok(self
            .storage_mut()
            .await
            .clamp_last_fully_indexed_ledger(max_ledger)
            .await?)
    }

    async fn list_pool_gvk_events(
        &self,
        pool_contract_id: &str,
        after: Option<(u32, String)>,
        limit: u32,
    ) -> Result<Vec<crate::gvk::GvkEvent>, Error> {
        Ok(self
            .storage()
            .await
            .list_pool_gvk_events(pool_contract_id, after, limit)
            .await?)
    }

    async fn pool_has_commitments(
        &self,
        pool_contract_id: &str,
        commitments: &[Field],
    ) -> Result<HashSet<Field>, Error> {
        Ok(self
            .storage()
            .await
            .pool_has_commitments(pool_contract_id, commitments)
            .await?)
    }
}

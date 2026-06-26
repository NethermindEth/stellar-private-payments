use std::{cell::RefCell, path::PathBuf, sync::Arc};

use prover::flows::TransactParams;
use state::{SqliteStorage, StoredUserKeys};
use stellar::ContractDataStorage;
use tx_planner::SpendableNote;
use types::{
    ContractsEventData, EncryptionPublicKey, NotePublicKey, SyncMetadata, UserNoteSummary,
};

use super::{
    Storage, map_build_params, map_user_keys, pool_notes_from_storage, spendable_notes_from_storage,
};
use crate::{
    core::process_local_state,
    disclosure::{DisclosureInputs, DisclosureInputsRequest, map_build_disclosure_inputs},
    error::PoolError,
    transact::TransactRequest,
};

/// In-process SQLite wallet storage (native only).
pub struct LocalStorage {
    path: Arc<PathBuf>,
    db: RefCell<SqliteStorage>,
}

impl LocalStorage {
    pub fn open(storage_path: &str) -> Result<Self, PoolError> {
        let path = PathBuf::from(storage_path);
        let db = SqliteStorage::connect_file(&path)
            .map_err(|e| PoolError::Other(format!("open storage: {e:#}")))?;
        Ok(Self {
            path: Arc::new(path),
            db: RefCell::new(db),
        })
    }

    pub fn storage(&self) -> std::cell::Ref<'_, SqliteStorage> {
        self.db.borrow()
    }

    pub fn storage_mut(&self) -> std::cell::RefMut<'_, SqliteStorage> {
        self.db.borrow_mut()
    }
}

#[async_trait::async_trait(?Send)]
impl ContractDataStorage for LocalStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        self.storage().get_sync_metadata()
    }

    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
        self.storage_mut().save_events_batch(&batch)
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        self.storage_mut()
            .save_sync_progress(&metadata, fully_indexed)
    }
}

#[async_trait::async_trait(?Send)]
impl Storage for LocalStorage {
    fn fork(&self) -> Result<Self, PoolError> {
        let db = SqliteStorage::connect_file(self.path.as_path())
            .map_err(|e| PoolError::Other(format!("fork storage: {e:#}")))?;
        Ok(Self {
            path: Arc::clone(&self.path),
            db: RefCell::new(db),
        })
    }

    async fn ensure_ready(&self) -> Result<(), PoolError> {
        Ok(())
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError> {
        spendable_notes_from_storage(&self.storage(), pool_contract_id, user_address)
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, PoolError> {
        pool_notes_from_storage(&self.storage(), pool_contract_id, user_address)
    }

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError> {
        map_build_params(crate::transact::build_transact_params(&self.storage(), req))
    }

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<DisclosureInputs, PoolError> {
        map_build_disclosure_inputs(crate::disclosure::build_disclosure_inputs(
            &self.storage(),
            req,
        ))
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError> {
        map_user_keys(&self.storage(), user_address)
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        let keys = map_user_keys(&self.storage(), user_address)?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }

    async fn process_pending_state(&self) -> Result<(), PoolError> {
        process_local_state(&mut self.storage_mut())
    }
}

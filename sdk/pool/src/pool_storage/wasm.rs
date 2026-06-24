use std::{cell::RefCell, rc::Rc};

use prover::flows::TransactParams;
use state::{Storage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{ContractConfig, EncryptionPublicKey, NotePublicKey};

use super::{PoolStorage, map_build_params, map_user_keys, spendable_wallet_from_storage};
use crate::{
    core::process_local_state,
    error::PoolError,
    transact::{TransactRequest, build_transact_params},
};

/// In-process SQLite backend for embedded WASM (tests / non-web targets).
pub struct LocalPoolBackend {
    storage: Rc<RefCell<Storage>>,
    indexer: RefCell<Option<stellar::Indexer<SharedContractStorage>>>,
}

#[derive(Clone)]
pub(crate) struct SharedContractStorage(pub Rc<RefCell<Storage>>);

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for SharedContractStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<types::SyncMetadata>> {
        Ok(self.0.borrow().get_sync_metadata()?)
    }

    async fn save_events_batch(&self, batch: types::ContractsEventData) -> anyhow::Result<()> {
        self.0.borrow_mut().save_events_batch(&batch)?;
        Ok(())
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<types::SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        self.0
            .borrow_mut()
            .save_sync_progress(&metadata, fully_indexed)?;
        Ok(())
    }
}

impl LocalPoolBackend {
    pub fn open(storage_path: &str) -> Result<Self, PoolError> {
        let storage = Storage::connect_file(storage_path)
            .map_err(|e| PoolError::Other(format!("open storage: {e:#}")))?;
        Ok(Self {
            storage: Rc::new(RefCell::new(storage)),
            indexer: RefCell::new(None),
        })
    }

    pub fn storage(&self) -> &Rc<RefCell<Storage>> {
        &self.storage
    }

    async fn ensure_indexer(
        &self,
        rpc_url: &str,
        contract_config: &ContractConfig,
    ) -> Result<(), PoolError> {
        if self.indexer.borrow().is_some() {
            return Ok(());
        }
        let shared = SharedContractStorage(Rc::clone(&self.storage));
        let indexer = stellar::Indexer::init(rpc_url, shared, contract_config)
            .await
            .map_err(|e| PoolError::Other(format!("open indexer: {e:#}")))?;
        *self.indexer.borrow_mut() = Some(indexer);
        Ok(())
    }

    async fn fetch_contract_events(&self) -> Result<bool, PoolError> {
        let indexer_guard = self.indexer.borrow();
        let indexer = indexer_guard.as_ref().ok_or(PoolError::NotInitialized)?;
        indexer
            .fetch_contract_events()
            .await
            .map_err(|e| PoolError::Other(format!("fetch events: {e:#}")))
    }

    fn sync_metadata_min_ledger(&self) -> Result<u32, PoolError> {
        Ok(self
            .storage
            .borrow()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0))
    }

    fn sync_metadata_max_ledger(&self, fallback: u32) -> Result<u32, PoolError> {
        Ok(self
            .storage
            .borrow()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .max()
            .unwrap_or(fallback))
    }
}

#[async_trait::async_trait(?Send)]
impl PoolStorage for LocalPoolBackend {
    async fn ensure_ready(&self) -> Result<(), PoolError> {
        Ok(())
    }

    async fn spendable_wallet(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError> {
        let storage = self.storage.borrow();
        spendable_wallet_from_storage(&storage, pool_contract_id, user_address)
    }

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError> {
        let storage = self.storage.borrow();
        map_build_params(build_transact_params(&storage, req))
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError> {
        let storage = self.storage.borrow();
        map_user_keys(&storage, user_address)
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        let keys = self.user_keys(user_address).await?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }

    async fn sync_indexer(
        &self,
        rpc_url: &str,
        contract_config: &ContractConfig,
    ) -> Result<(u32, u32), PoolError> {
        let from_ledger = self.sync_metadata_min_ledger()?;
        self.ensure_indexer(rpc_url, contract_config).await?;
        while self.fetch_contract_events().await? {}
        process_local_state(&mut *self.storage.borrow_mut())?;
        let to_ledger = self.sync_metadata_max_ledger(from_ledger)?;
        Ok((from_ledger, to_ledger))
    }
}

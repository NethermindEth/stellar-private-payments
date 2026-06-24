use prover::flows::TransactParams;
use state::{Storage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{ContractConfig, EncryptionPublicKey, NotePublicKey};

use super::{PoolStorage, map_build_params, map_user_keys, spendable_wallet_from_storage};
use crate::{core::process_local_state, error::PoolError, transact::TransactRequest};

/// In-process SQLite + synchronous contract indexer (native only).
pub struct NativePoolBackend {
    indexer: std::cell::RefCell<crate::blocking::Indexer>,
}

impl NativePoolBackend {
    pub fn open(
        rpc_url: &str,
        storage_path: &str,
        contract_config: &ContractConfig,
    ) -> Result<Self, PoolError> {
        let storage = Storage::connect_file(storage_path)
            .map_err(|e| PoolError::Other(format!("open storage: {e:#}")))?;
        let indexer = crate::blocking::Indexer::new(rpc_url, storage, contract_config)
            .map_err(|e| PoolError::Other(format!("open indexer: {e:#}")))?;
        Ok(Self {
            indexer: std::cell::RefCell::new(indexer),
        })
    }

    pub fn storage(&self) -> std::cell::Ref<'_, Storage> {
        std::cell::Ref::map(self.indexer.borrow(), |indexer| indexer.storage())
    }

    pub fn storage_mut(&self) -> std::cell::RefMut<'_, Storage> {
        std::cell::RefMut::map(self.indexer.borrow_mut(), |indexer| indexer.storage_mut())
    }

    pub fn indexer_mut(&self) -> std::cell::RefMut<'_, crate::blocking::Indexer> {
        self.indexer.borrow_mut()
    }

    async fn fetch_contract_events(&self) -> Result<bool, PoolError> {
        self.indexer
            .borrow_mut()
            .fetch_contract_events()
            .map_err(|e| PoolError::Other(format!("fetch events: {e:#}")))
    }

    fn sync_metadata_min_ledger(&self) -> Result<u32, PoolError> {
        Ok(self
            .storage()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0))
    }

    fn sync_metadata_max_ledger(&self, fallback: u32) -> Result<u32, PoolError> {
        Ok(self
            .storage()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .max()
            .unwrap_or(fallback))
    }
}

#[async_trait::async_trait(?Send)]
impl PoolStorage for NativePoolBackend {
    async fn ensure_ready(&self) -> Result<(), PoolError> {
        Ok(())
    }

    async fn spendable_wallet(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError> {
        spendable_wallet_from_storage(&self.storage(), pool_contract_id, user_address)
    }

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError> {
        map_build_params(crate::transact::build_transact_params(&self.storage(), req))
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

    async fn sync_indexer(
        &self,
        _rpc_url: &str,
        _contract_config: &ContractConfig,
    ) -> Result<(u32, u32), PoolError> {
        let from_ledger = self.sync_metadata_min_ledger()?;
        while self.fetch_contract_events().await? {}
        process_local_state(&mut *self.storage_mut())?;
        let to_ledger = self.sync_metadata_max_ledger(from_ledger)?;
        Ok((from_ledger, to_ledger))
    }
}

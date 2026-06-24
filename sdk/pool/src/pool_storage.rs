//! Pluggable async wallet storage for [`crate::pool::PrivatePool`].

#[cfg(target_arch = "wasm32")]
use std::{cell::RefCell, rc::Rc};

use prover::flows::TransactParams;
use state::{Storage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{EncryptionPublicKey, NotePublicKey};

use crate::{
    error::PoolError,
    transact::{BuildTransactParams, TransactRequest},
};

#[cfg(target_arch = "wasm32")]
use crate::transact::build_transact_params;

pub(crate) fn map_build_params(
    result: anyhow::Result<BuildTransactParams>,
) -> Result<TransactParams, PoolError> {
    match result.map_err(|e| PoolError::Other(e.to_string()))? {
        BuildTransactParams::Ready(params) => Ok(params),
        BuildTransactParams::MembershipSync(status) => Err(PoolError::MembershipSync(status)),
    }
}

pub(crate) fn map_user_keys(
    storage: &Storage,
    user_address: &str,
) -> Result<StoredUserKeys, PoolError> {
    storage
        .get_user_keys(user_address)
        .map_err(|e| PoolError::Other(e.to_string()))?
        .ok_or_else(|| {
            PoolError::Other(format!(
                "address {user_address} should generate privacy keys and ASP secret first"
            ))
        })
}

pub(crate) fn spendable_wallet_from_storage(
    storage: &Storage,
    pool_contract_id: &str,
    user_address: &str,
) -> Result<Vec<SpendableNote>, PoolError> {
    storage
        .list_unspent_user_notes(pool_contract_id, user_address)
        .map_err(|e| PoolError::Other(e.to_string()))
        .map(|notes| {
            notes
                .into_iter()
                .map(|n| SpendableNote {
                    commitment: n.id,
                    amount: n.amount,
                })
                .collect()
        })
}

/// Wallet + transact-param reads for [`crate::pool::PrivatePool`].
#[async_trait::async_trait(?Send)]
pub trait PoolStorage {
    async fn ensure_ready(&self) -> Result<(), PoolError>;

    async fn spendable_wallet(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError>;

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError>;

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError>;

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError>;

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, PoolError> {
        Ok(self.user_keys(user_address).await?.note_keypair.public)
    }
}

/// In-process SQLite backend for embedded WASM (tests / non-web targets).
#[cfg(target_arch = "wasm32")]
pub struct LocalPoolBackend {
    storage: Rc<RefCell<Storage>>,
    indexer: RefCell<Option<stellar::Indexer<SharedContractStorage>>>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub(crate) struct SharedContractStorage(pub Rc<RefCell<Storage>>);

#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
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

    pub async fn ensure_indexer(
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

    pub async fn fetch_contract_events(&self) -> Result<bool, PoolError> {
        let indexer = self
            .indexer
            .borrow()
            .as_ref()
            .ok_or(PoolError::NotInitialized)?;
        indexer
            .fetch_contract_events()
            .await
            .map_err(|e| PoolError::Other(format!("fetch events: {e:#}"))?)
    }

    pub fn sync_metadata_min_ledger(&self) -> Result<u32, PoolError> {
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

    pub fn sync_metadata_max_ledger(&self, fallback: u32) -> Result<u32, PoolError> {
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

#[cfg(target_arch = "wasm32")]
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
}

#[cfg(not(target_arch = "wasm32"))]
pub struct NativePoolBackend {
    indexer: std::cell::RefCell<crate::blocking::Indexer>,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativePoolBackend {
    pub fn open(
        rpc_url: &str,
        storage_path: &str,
        contract_config: &types::ContractConfig,
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

    pub async fn fetch_contract_events(&self) -> Result<bool, PoolError> {
        self.indexer
            .borrow_mut()
            .fetch_contract_events()
            .map_err(|e| PoolError::Other(format!("fetch events: {e:#}")))
    }

    pub fn sync_metadata_min_ledger(&self) -> Result<u32, PoolError> {
        Ok(self
            .storage()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0))
    }

    pub fn sync_metadata_max_ledger(&self, fallback: u32) -> Result<u32, PoolError> {
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

#[cfg(not(target_arch = "wasm32"))]
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
        let keys = self.user_keys(user_address).await?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }
}

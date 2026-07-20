use std::{cell::RefCell, path::PathBuf};

use prover::flows::TransactParams;
use state::{SqliteStorage, StoredUserKeys};
use stellar::ContractDataStorage;
use tx_planner::SpendableNote;
use types::{
    ContractConfig, ContractsEventData, EncryptionPublicKey, Field, NotePublicKey,
    OperationalFeedItem, PortfolioBalance, RecipientLookup, SyncMetadata, UserNoteSummary,
};

use super::{
    Storage, map_build_params, map_user_keys, operational_feed_from_storage,
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
    db: RefCell<SqliteStorage>,
}

impl LocalStorage {
    pub fn open(storage_path: &str) -> Result<Self, Error> {
        let path = PathBuf::from(storage_path);
        let db = SqliteStorage::connect_file(&path)
            .map_err(|e| Error::Other(format!("open storage: {e:#}")))?;
        Ok(Self {
            path,
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
    fn fork(&self) -> Result<Self, Error> {
        let db = SqliteStorage::connect_file(self.path.as_path())
            .map_err(|e| Error::Other(format!("fork storage: {e:#}")))?;
        Ok(Self {
            path: self.path.clone(),
            db: RefCell::new(db),
        })
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, Error> {
        spendable_notes_from_storage(&self.storage(), pool_contract_id, user_address)
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        pool_notes_from_storage(&self.storage(), pool_contract_id, user_address)
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        config: &ContractConfig,
    ) -> Result<Vec<PortfolioBalance>, Error> {
        portfolio_balances_from_storage(&self.storage(), user_address, config)
    }

    async fn list_user_notes(
        &self,
        user_address: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        user_notes_from_storage(&self.storage(), user_address, limit)
    }

    async fn operational_feed(
        &self,
        limit: u32,
        config: &ContractConfig,
    ) -> Result<Vec<OperationalFeedItem>, Error> {
        operational_feed_from_storage(&self.storage(), limit, config)
    }

    async fn recipient_lookup(
        &self,
        address: &str,
        config: &ContractConfig,
    ) -> Result<RecipientLookup, Error> {
        recipient_lookup_from_storage(&self.storage(), address, config)
    }

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error> {
        map_build_params(crate::transact::build_transact_params(&self.storage(), req))
    }

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error> {
        map_build_disclosure_inputs(crate::disclosure::build_disclosure_inputs(
            &self.storage(),
            req,
        ))
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, Error> {
        map_user_keys(&self.storage(), user_address)
    }

    async fn asp_secret(&self, user_address: &str) -> Result<Field, Error> {
        Ok(map_user_keys(&self.storage(), user_address)?.membership_blinding)
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let keys = map_user_keys(&self.storage(), user_address)?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }

    async fn registered_public_keys(
        &self,
        address: &str,
        _public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let entry = self
            .storage()
            .lookup_public_key_by_address(address)
            .map_err(|e| Error::Other(format!("lookup recipient: {e:#}")))?
            .ok_or_else(|| {
                Error::Other(format!(
                    "recipient {address} not found in the public key registry; \
                     they must register keys on-chain"
                ))
            })?;
        Ok((entry.note_key, entry.encryption_key))
    }

    async fn process_pending_state(&self) -> Result<(), Error> {
        process_local_state(&mut self.storage_mut())
    }
}

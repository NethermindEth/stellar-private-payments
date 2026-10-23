use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

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
    registration::{RegistrationInputs, RegistrationRequest, build_registration_inputs},
    transact::TransactRequest,
};

/// In-process SQLite wallet storage (native only).
pub struct LocalStorage {
    path: PathBuf,
    #[cfg(feature = "encrypted-storage")]
    database_key: Option<std::sync::Arc<crate::state::database_key::DatabaseKey>>,
    db: Mutex<SqliteStorage>,
}

impl LocalStorage {
    /// Open or create plaintext persistent storage.
    #[cfg(feature = "unencrypted-storage")]
    pub fn open(storage_path: &str) -> Result<Self, Error> {
        let path = PathBuf::from(storage_path);
        let db = SqliteStorage::connect_file(&path).context("open storage")?;
        Ok(Self {
            path,
            #[cfg(feature = "encrypted-storage")]
            database_key: None,
            db: Mutex::new(db),
        })
    }

    /// Open persistent storage with an explicit key and create/open policy.
    #[cfg(feature = "encrypted-storage")]
    pub fn open_encrypted(
        storage_path: &str,
        key: crate::state::database_key::DatabaseKey,
        purpose: crate::state::database_key::OpenPurpose,
    ) -> Result<Self, Error> {
        let path = PathBuf::from(storage_path);
        let db = SqliteStorage::connect_encrypted(&path, &key, purpose)?;
        Ok(Self {
            path,
            db: Mutex::new(db),
            database_key: Some(std::sync::Arc::new(key)),
        })
    }

    /// Reopen an encrypted database already unlocked with this key.
    #[cfg(feature = "encrypted-storage")]
    pub fn open_with_key(
        storage_path: &str,
        key: &crate::state::database_key::DatabaseKey,
    ) -> Result<Self, Error> {
        let path = PathBuf::from(storage_path);
        let db = SqliteStorage::reopen_encrypted(&path, key).context("open encrypted storage")?;
        Ok(Self {
            path,
            database_key: Some(std::sync::Arc::new(
                crate::state::database_key::DatabaseKey::new(**key),
            )),
            db: Mutex::new(db),
        })
    }

    pub fn storage(&self) -> MutexGuard<'_, SqliteStorage> {
        self.db.lock().expect("storage lock poisoned")
    }

    pub fn storage_mut(&self) -> MutexGuard<'_, SqliteStorage> {
        self.db.lock().expect("storage lock poisoned")
    }

    /// Open an independent connection, retaining the key for encrypted storage.
    pub(crate) fn fork_local(&self) -> Result<Self, Error> {
        #[cfg(feature = "encrypted-storage")]
        let db = match &self.database_key {
            Some(key) => SqliteStorage::reopen_encrypted(&self.path, key)
                .context("fork encrypted storage")?,
            #[cfg(feature = "unencrypted-storage")]
            None => SqliteStorage::reopen_plaintext(&self.path).context("fork storage")?,
            #[cfg(not(feature = "unencrypted-storage"))]
            None => unreachable!("only `open` creates storage without a key"),
        };
        #[cfg(not(feature = "encrypted-storage"))]
        let db = SqliteStorage::reopen_plaintext(&self.path).context("fork storage")?;
        Ok(Self {
            path: self.path.clone(),
            #[cfg(feature = "encrypted-storage")]
            database_key: self.database_key.clone(),
            db: Mutex::new(db),
        })
    }

    pub fn get_gvk_authority_setting(&self) -> Result<Option<GvkAuthoritySetting>, Error> {
        self.storage()
            .get_gvk_authority_setting()
            .map_err(|e| Error::Other(anyhow::anyhow!("read GVK authority setting: {e:#}")))
    }

    pub fn set_gvk_authority_setting(&self, setting: &GvkAuthoritySetting) -> Result<(), Error> {
        self.storage_mut()
            .set_gvk_authority_setting(setting)
            .map_err(|e| Error::Other(anyhow::anyhow!("write GVK authority setting: {e:#}")))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Storage for LocalStorage {
    fn fork(&self) -> Result<crate::storage::StorageHandle, Error> {
        let forked = self.fork_local()?;
        Ok(crate::storage::StorageHandle::from(forked))
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<Vec<SpendableNote>, Error> {
        spendable_notes_from_storage(&self.storage(), pool_contract_id, user_address, kdf_domain)
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        pool_notes_from_storage(&self.storage(), pool_contract_id, user_address, kdf_domain)
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        kdf_domain: &str,
        enabled_pools: &[PortfolioPoolEntry],
    ) -> Result<Vec<PortfolioBalance>, Error> {
        portfolio_balances_from_storage(&self.storage(), user_address, kdf_domain, enabled_pools)
    }

    async fn list_user_notes(
        &self,
        user_address: &str,
        kdf_domain: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        user_notes_from_storage(&self.storage(), user_address, kdf_domain, limit)
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

    async fn build_registration_inputs(
        &self,
        req: &RegistrationRequest,
    ) -> Result<RegistrationInputs, Error> {
        build_registration_inputs(&self.storage(), req)
    }

    async fn privacy_keys_exist(
        &self,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<bool, Error> {
        Ok(self
            .storage()
            .get_private_keys(user_address, kdf_domain)
            .context("check stored private keys")?
            .is_some())
    }

    async fn save_private_keys(
        &self,
        user_address: &str,
        kdf_domain: &str,
        note_keypair: &NoteKeyPair,
        encryption_keypair: &EncryptionKeyPair,
        membership_blinding: &Field,
    ) -> Result<(), Error> {
        Ok(self
            .storage_mut()
            .save_encryption_and_note_keypairs(
                user_address,
                kdf_domain,
                note_keypair,
                encryption_keypair,
                membership_blinding,
            )
            .context("save private keys")?)
    }

    async fn asp_secret(&self, user_address: &str, kdf_domain: &str) -> Result<Field, Error> {
        Ok(map_private_keys(&self.storage(), user_address, kdf_domain)?.membership_blinding)
    }

    async fn privacy_keys(
        &self,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let keys = map_private_keys(&self.storage(), user_address, kdf_domain)?;
        Ok((keys.note_keypair.public, keys.encryption_keypair.public))
    }

    async fn registered_privacy_keys(
        &self,
        address: &str,
        public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        let entry = self
            .storage()
            .lookup_public_key_by_address(address, public_key_registry_contract_id)
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
        process_local_state(&mut self.storage_mut())
    }

    async fn clear_indexing_cursors(&self) -> Result<(), Error> {
        Ok(self.storage_mut().clear_indexing_cursors()?)
    }

    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error> {
        Ok(self
            .storage_mut()
            .clamp_last_fully_indexed_ledger(max_ledger)?)
    }

    async fn list_pool_gvk_events(
        &self,
        pool_contract_id: &str,
        after: Option<(u32, String)>,
        limit: u32,
    ) -> Result<Vec<crate::gvk::GvkEvent>, Error> {
        Ok(self
            .storage()
            .list_pool_gvk_events(pool_contract_id, after, limit)?)
    }

    async fn pool_has_commitments(
        &self,
        pool_contract_id: &str,
        commitments: &[Field],
    ) -> Result<HashSet<Field>, Error> {
        Ok(self
            .storage()
            .pool_has_commitments(pool_contract_id, commitments)?)
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "unencrypted-storage"))]
mod tests {
    use super::LocalStorage;
    use crate::state::SqliteStorage;
    use std::path::{Path, PathBuf};

    // Removes the listed files when the test ends, even on failure.
    struct Cleanup(Vec<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn unique_name(prefix: &str) -> anyhow::Result<String> {
        let mut suffix = [0; 8];
        getrandom::getrandom(&mut suffix)?;
        Ok(format!("{prefix}-{}.sqlite", hex::encode(suffix)))
    }

    fn assert_set_and_forked(storage: &LocalStorage) -> anyhow::Result<()> {
        storage.storage_mut().set_setting_json("plain", &"stored")?;
        let fork = storage.fork_local()?;
        let forked = std::thread::spawn(move || fork.storage().get_setting_json::<String>("plain"))
            .join()
            .expect("fork thread")?;
        assert_eq!(forked.as_deref(), Some("stored"));
        Ok(())
    }

    #[test]
    fn plaintext_storage_round_trips_and_forks() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(unique_name("spp-plaintext")?);
        let _cleanup = Cleanup(vec![path.clone()]);
        let path_str = path.to_str().expect("UTF-8 temp path");
        assert_set_and_forked(&LocalStorage::open(path_str)?)?;
        let reopened = SqliteStorage::connect_existing_plaintext(&path)?
            .get_setting_json::<String>("plain")?;
        assert_eq!(reopened.as_deref(), Some("stored"));
        assert!(std::fs::read(&path)?.starts_with(b"SQLite format 3"));
        Ok(())
    }

    // A relative "file:" name must stay a literal filename for forks too,
    // not a URI that selects another database.
    #[cfg(unix)]
    #[test]
    fn plaintext_forks_keep_literal_file_names() -> anyhow::Result<()> {
        let name = format!("file:{}", unique_name("spp-literal")?);
        let uri_target = name.trim_start_matches("file:").to_owned();
        let _cleanup = Cleanup(vec![PathBuf::from(&name), PathBuf::from(&uri_target)]);
        assert_set_and_forked(&LocalStorage::open(&name)?)?;
        assert!(Path::new(&name).exists());
        assert!(!Path::new(&uri_target).exists());
        Ok(())
    }

    #[test]
    fn existing_plaintext_open_rejects_missing_and_empty_files() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(unique_name("spp-missing")?);
        let _cleanup = Cleanup(vec![path.clone()]);
        assert!(SqliteStorage::connect_existing_plaintext(&path).is_err());
        assert!(!path.exists());
        std::fs::write(&path, b"")?;
        assert!(SqliteStorage::connect_existing_plaintext(&path).is_err());
        assert_eq!(std::fs::metadata(&path)?.len(), 0);
        Ok(())
    }

    // Stands in for an encrypted database and its hot journal: neither has a
    // plaintext SQLite header, so every plaintext open must refuse it before
    // SQLite can replay or delete the journal.
    #[test]
    fn plaintext_opens_reject_unreadable_database_and_keep_journal() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(unique_name("spp-ciphertext")?);
        let journal = PathBuf::from(format!("{}-journal", path.display()));
        let _cleanup = Cleanup(vec![path.clone(), journal.clone()]);
        let mut database = vec![0; 8192];
        getrandom::getrandom(&mut database)?;
        let mut hot_journal = vec![0; 4096];
        getrandom::getrandom(&mut hot_journal)?;
        std::fs::write(&path, &database)?;
        std::fs::write(&journal, &hot_journal)?;
        assert!(SqliteStorage::connect_file(&path).is_err());
        assert!(SqliteStorage::connect_existing_plaintext(&path).is_err());
        assert!(LocalStorage::open(path.to_str().expect("UTF-8 temp path")).is_err());
        assert_eq!(std::fs::read(&path)?, database);
        assert_eq!(std::fs::read(&journal)?, hot_journal);
        Ok(())
    }
}

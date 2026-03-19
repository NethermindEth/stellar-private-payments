//! Temporary in-memory storage backend for the WASM target.
//!
//! TODO: Replace with `sqlite-wasm-rs` + `SyncAccessHandlePoolVFS` (OPFS) when
//! porting the first JS state module to Rust requires persistent browser storage.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::types::{
    AspMembershipLeaf, PoolEncryptedOutput, PoolLeaf, PoolNullifier, PublicKeyEntry,
    RetentionConfig, SyncMetadata, UserNote,
};

/// In-memory storage for the WASM target.
///
/// `BTreeMap` keys match SQLite primary keys; ordered iteration mirrors
/// IndexedDB cursor semantics. `RefCell` allows `&self` mutation (WASM is
/// single-threaded).
pub struct Storage {
    pool_leaves: RefCell<BTreeMap<u32, PoolLeaf>>,
    pool_nullifiers: RefCell<BTreeMap<String, PoolNullifier>>,
    pool_encrypted_outputs: RefCell<BTreeMap<String, PoolEncryptedOutput>>,
    asp_membership_leaves: RefCell<BTreeMap<u32, AspMembershipLeaf>>,
    user_notes: RefCell<BTreeMap<String, UserNote>>,
    public_keys: RefCell<BTreeMap<String, PublicKeyEntry>>,
    sync_metadata: RefCell<BTreeMap<String, SyncMetadata>>,
    retention_config: RefCell<BTreeMap<String, RetentionConfig>>,
}

impl Storage {
    /// Opens a named storage instance (name ignored — always in-memory).
    pub fn open(_path: &str) -> anyhow::Result<Self> {
        Ok(Self::open_in_memory()?)
    }

    /// Opens a fresh in-memory storage instance.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Ok(Self {
            pool_leaves: RefCell::new(BTreeMap::new()),
            pool_nullifiers: RefCell::new(BTreeMap::new()),
            pool_encrypted_outputs: RefCell::new(BTreeMap::new()),
            asp_membership_leaves: RefCell::new(BTreeMap::new()),
            user_notes: RefCell::new(BTreeMap::new()),
            public_keys: RefCell::new(BTreeMap::new()),
            sync_metadata: RefCell::new(BTreeMap::new()),
            retention_config: RefCell::new(BTreeMap::new()),
        })
    }

    // -----------------------------------------------------------------------
    // pool_leaves
    // -----------------------------------------------------------------------

    /// Inserts or replaces a pool leaf.
    pub fn put_pool_leaf(&self, leaf: &PoolLeaf) -> anyhow::Result<()> {
        self.pool_leaves.borrow_mut().insert(leaf.index, leaf.clone());
        Ok(())
    }

    /// Iterates over pool leaves in ascending index order.
    pub fn iterate_pool_leaves(
        &self,
        mut callback: impl FnMut(PoolLeaf) -> bool,
    ) -> anyhow::Result<()> {
        for leaf in self.pool_leaves.borrow().values() {
            if !callback(leaf.clone()) {
                break;
            }
        }
        Ok(())
    }

    /// Returns the total number of pool leaves.
    pub fn count_pool_leaves(&self) -> anyhow::Result<u32> {
        u32::try_from(self.pool_leaves.borrow().len())
            .map_err(|e| anyhow::anyhow!("count overflow: {e}"))
    }

    /// Inserts or replaces a batch of pool leaves.
    pub fn put_pool_leaves_batch(&self, leaves: &[PoolLeaf]) -> anyhow::Result<()> {
        let mut map = self.pool_leaves.borrow_mut();
        for leaf in leaves {
            map.insert(leaf.index, leaf.clone());
        }
        Ok(())
    }

    /// Deletes all pool leaves.
    pub fn clear_pool_leaves(&self) -> anyhow::Result<()> {
        self.pool_leaves.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // pool_nullifiers
    // -----------------------------------------------------------------------

    /// Inserts or replaces a nullifier record.
    pub fn put_nullifier(&self, nullifier: &PoolNullifier) -> anyhow::Result<()> {
        self.pool_nullifiers
            .borrow_mut()
            .insert(nullifier.nullifier.clone(), nullifier.clone());
        Ok(())
    }

    /// Returns the nullifier record for `nullifier`, or `None` if unspent.
    pub fn get_nullifier(&self, nullifier: &str) -> anyhow::Result<Option<PoolNullifier>> {
        Ok(self.pool_nullifiers.borrow().get(nullifier).cloned())
    }

    /// Returns the total number of spent nullifiers.
    pub fn count_nullifiers(&self) -> anyhow::Result<u32> {
        u32::try_from(self.pool_nullifiers.borrow().len())
            .map_err(|e| anyhow::anyhow!("count overflow: {e}"))
    }

    /// Deletes all nullifiers.
    pub fn clear_nullifiers(&self) -> anyhow::Result<()> {
        self.pool_nullifiers.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // pool_encrypted_outputs
    // -----------------------------------------------------------------------

    /// Inserts or replaces an encrypted output.
    pub fn put_encrypted_output(&self, output: &PoolEncryptedOutput) -> anyhow::Result<()> {
        self.pool_encrypted_outputs
            .borrow_mut()
            .insert(output.commitment.clone(), output.clone());
        Ok(())
    }

    /// Returns all encrypted outputs.
    pub fn get_all_encrypted_outputs(&self) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
        Ok(self.pool_encrypted_outputs.borrow().values().cloned().collect())
    }

    /// Returns encrypted outputs with `ledger >= from_ledger`.
    pub fn get_encrypted_outputs_from(
        &self,
        from_ledger: u32,
    ) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
        Ok(self
            .pool_encrypted_outputs
            .borrow()
            .values()
            .filter(|o| o.ledger >= from_ledger)
            .cloned()
            .collect())
    }

    /// Deletes all encrypted outputs.
    pub fn clear_encrypted_outputs(&self) -> anyhow::Result<()> {
        self.pool_encrypted_outputs.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // asp_membership_leaves
    // -----------------------------------------------------------------------

    /// Inserts or replaces an ASP membership leaf.
    pub fn put_asp_membership_leaf(&self, leaf: &AspMembershipLeaf) -> anyhow::Result<()> {
        self.asp_membership_leaves
            .borrow_mut()
            .insert(leaf.index, leaf.clone());
        Ok(())
    }

    /// Iterates over ASP membership leaves in ascending index order.
    pub fn iterate_asp_membership_leaves(
        &self,
        mut callback: impl FnMut(AspMembershipLeaf) -> bool,
    ) -> anyhow::Result<()> {
        for leaf in self.asp_membership_leaves.borrow().values() {
            if !callback(leaf.clone()) {
                break;
            }
        }
        Ok(())
    }

    /// Returns the first ASP membership leaf matching `leaf_hash`, or `None`.
    pub fn get_asp_membership_leaf_by_hash(
        &self,
        leaf_hash: &str,
    ) -> anyhow::Result<Option<AspMembershipLeaf>> {
        Ok(self
            .asp_membership_leaves
            .borrow()
            .values()
            .find(|l| l.leaf == leaf_hash)
            .cloned())
    }

    /// Returns the total number of ASP membership leaves.
    pub fn count_asp_membership_leaves(&self) -> anyhow::Result<u32> {
        u32::try_from(self.asp_membership_leaves.borrow().len())
            .map_err(|e| anyhow::anyhow!("count overflow: {e}"))
    }

    /// Inserts or replaces a batch of ASP membership leaves.
    pub fn put_asp_membership_leaves_batch(
        &self,
        leaves: &[AspMembershipLeaf],
    ) -> anyhow::Result<()> {
        let mut map = self.asp_membership_leaves.borrow_mut();
        for leaf in leaves {
            map.insert(leaf.index, leaf.clone());
        }
        Ok(())
    }

    /// Deletes all ASP membership leaves.
    pub fn clear_asp_membership_leaves(&self) -> anyhow::Result<()> {
        self.asp_membership_leaves.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // user_notes
    // -----------------------------------------------------------------------

    /// Inserts or replaces a user note.
    pub fn put_note(&self, note: &UserNote) -> anyhow::Result<()> {
        self.user_notes.borrow_mut().insert(note.id.clone(), note.clone());
        Ok(())
    }

    /// Returns the note with the given id, or `None`.
    pub fn get_note(&self, id: &str) -> anyhow::Result<Option<UserNote>> {
        Ok(self.user_notes.borrow().get(id).cloned())
    }

    /// Returns all notes belonging to `owner`.
    pub fn get_notes_by_owner(&self, owner: &str) -> anyhow::Result<Vec<UserNote>> {
        Ok(self
            .user_notes
            .borrow()
            .values()
            .filter(|n| n.owner == owner)
            .cloned()
            .collect())
    }

    /// Returns every note across all owners.
    pub fn get_all_notes(&self) -> anyhow::Result<Vec<UserNote>> {
        Ok(self.user_notes.borrow().values().cloned().collect())
    }

    /// Deletes the note with the given id.
    pub fn delete_note(&self, id: &str) -> anyhow::Result<()> {
        self.user_notes.borrow_mut().remove(id);
        Ok(())
    }

    /// Deletes all notes.
    pub fn clear_notes(&self) -> anyhow::Result<()> {
        self.user_notes.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // registered_public_keys
    // -----------------------------------------------------------------------

    /// Inserts or replaces a public-key registration.
    pub fn put_public_key(&self, entry: &PublicKeyEntry) -> anyhow::Result<()> {
        self.public_keys
            .borrow_mut()
            .insert(entry.address.clone(), entry.clone());
        Ok(())
    }

    /// Returns the public-key record for `address`, or `None`.
    pub fn get_public_key(&self, address: &str) -> anyhow::Result<Option<PublicKeyEntry>> {
        Ok(self.public_keys.borrow().get(address).cloned())
    }

    /// Returns all public keys ordered by ledger descending.
    pub fn get_all_public_keys(&self) -> anyhow::Result<Vec<PublicKeyEntry>> {
        let mut entries: Vec<PublicKeyEntry> =
            self.public_keys.borrow().values().cloned().collect();
        entries.sort_by(|a, b| b.ledger.cmp(&a.ledger));
        Ok(entries)
    }

    /// Returns the total number of registered public keys.
    pub fn count_public_keys(&self) -> anyhow::Result<u32> {
        u32::try_from(self.public_keys.borrow().len())
            .map_err(|e| anyhow::anyhow!("count overflow: {e}"))
    }

    /// Deletes all registered public keys.
    pub fn clear_public_keys(&self) -> anyhow::Result<()> {
        self.public_keys.borrow_mut().clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // sync_metadata
    // -----------------------------------------------------------------------

    /// Returns the sync metadata for `network`, or `None`.
    pub fn get_sync_metadata(&self, network: &str) -> anyhow::Result<Option<SyncMetadata>> {
        Ok(self.sync_metadata.borrow().get(network).cloned())
    }

    /// Inserts or replaces sync metadata.
    pub fn put_sync_metadata(&self, metadata: &SyncMetadata) -> anyhow::Result<()> {
        self.sync_metadata
            .borrow_mut()
            .insert(metadata.network.clone(), metadata.clone());
        Ok(())
    }

    /// Deletes the sync metadata for `network`.
    pub fn delete_sync_metadata(&self, network: &str) -> anyhow::Result<()> {
        self.sync_metadata.borrow_mut().remove(network);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // retention_config
    // -----------------------------------------------------------------------

    /// Returns the cached retention config for `rpc_endpoint`, or `None`.
    pub fn get_retention_config(
        &self,
        rpc_endpoint: &str,
    ) -> anyhow::Result<Option<RetentionConfig>> {
        Ok(self.retention_config.borrow().get(rpc_endpoint).cloned())
    }

    /// Inserts or replaces a retention config.
    pub fn put_retention_config(&self, config: &RetentionConfig) -> anyhow::Result<()> {
        self.retention_config
            .borrow_mut()
            .insert(config.rpc_endpoint.clone(), config.clone());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Housekeeping
    // -----------------------------------------------------------------------

    /// Deletes all rows from every store.
    pub fn clear_all(&self) -> anyhow::Result<()> {
        self.pool_leaves.borrow_mut().clear();
        self.pool_nullifiers.borrow_mut().clear();
        self.pool_encrypted_outputs.borrow_mut().clear();
        self.asp_membership_leaves.borrow_mut().clear();
        self.user_notes.borrow_mut().clear();
        self.public_keys.borrow_mut().clear();
        self.sync_metadata.borrow_mut().clear();
        self.retention_config.borrow_mut().clear();
        Ok(())
    }
}

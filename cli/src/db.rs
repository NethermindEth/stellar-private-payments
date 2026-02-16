//! JSON file-backed storage for CLI state.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

/// An encrypted output entry: (commitment_hex, leaf_index, encrypted_data, ledger).
pub type EncryptedOutput = (String, u64, Vec<u8>, u64);

/// A user note stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserNote {
    /// Commitment hex (big-endian)
    pub id: String,
    /// Owner public key hex (big-endian)
    pub owner: String,
    /// BN254 note private key (hex, little-endian)
    pub private_key: String,
    /// Blinding factor (hex, little-endian)
    pub blinding: String,
    /// Amount in stroops
    pub amount: u64,
    /// Leaf index in the pool Merkle tree
    pub leaf_index: u64,
    /// Whether this note has been spent (0 = unspent, 1 = spent)
    pub spent: u64,
    /// Whether this was a received note (from transfer)
    pub is_received: u64,
    /// Ledger number when the note was created on-chain
    pub ledger: Option<u64>,
}

/// A registered public key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// Stellar G... address
    pub address: String,
    /// BN254 note public key (hex)
    pub note_key: String,
    /// X25519 encryption public key (hex)
    pub encryption_key: String,
    /// Ledger number
    pub ledger: u64,
}

/// Sync metadata for a contract type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SyncMetadata {
    last_ledger: u64,
    last_cursor: Option<String>,
}

/// A pool leaf entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoolLeaf {
    commitment: String,
    ledger: u64,
}

/// An encrypted output entry for storage (bytes stored as base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedOutputEntry {
    commitment: String,
    encrypted_output: String,
    ledger: u64,
}

/// An ASP membership leaf entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AspLeaf {
    leaf: String,
    ledger: u64,
}

/// In-memory store that is serialized to/from JSON.
#[derive(Debug, Serialize, Deserialize, Default)]
struct Store {
    sync_metadata: HashMap<String, SyncMetadata>,
    pool_leaves: BTreeMap<u64, PoolLeaf>,
    nullifiers: HashMap<String, u64>,
    encrypted_outputs: BTreeMap<u64, EncryptedOutputEntry>,
    asp_leaves: BTreeMap<u64, AspLeaf>,
    user_notes: HashMap<String, UserNote>,
    registered_keys: HashMap<String, RegisteredKey>,
}

/// Database path for a given network and pool.
pub fn db_path(network: &str, pool: &str) -> Result<PathBuf> {
    crate::config::pool_data_path(network, pool)
}

/// JSON file-backed database.
pub struct Database {
    path: Option<PathBuf>,
    store: RefCell<Store>,
}

impl Database {
    /// Open (or create) the database for the given network and pool.
    pub fn open(network: &str, pool: &str) -> Result<Self> {
        let path = db_path(network, pool)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create db dir {}", parent.display()))?;
        }
        let store = if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            serde_json::from_str(&data)
                .with_context(|| format!("Failed to parse {}", path.display()))?
        } else {
            Store::default()
        };
        Ok(Self {
            path: Some(path),
            store: RefCell::new(store),
        })
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Ok(Self {
            path: None,
            store: RefCell::new(Store::default()),
        })
    }

    /// Run schema migrations (no-op for JSON storage).
    pub fn migrate(&self) -> Result<()> {
        Ok(())
    }

    /// Persist the store to disk (no-op for in-memory).
    fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let data = serde_json::to_string_pretty(&*self.store.borrow())
            .context("Failed to serialize store")?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &data)
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("Failed to rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    // ========== Sync metadata ==========

    /// Get the last synced ledger for a contract type.
    pub fn get_last_ledger(&self, contract_type: &str) -> Result<u64> {
        Ok(self
            .store
            .borrow()
            .sync_metadata
            .get(contract_type)
            .map_or(0, |m| m.last_ledger))
    }

    /// Get the last cursor for a contract type.
    pub fn get_last_cursor(&self, contract_type: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .borrow()
            .sync_metadata
            .get(contract_type)
            .and_then(|m| m.last_cursor.clone()))
    }

    /// Update sync metadata.
    pub fn update_sync_metadata(
        &self,
        contract_type: &str,
        last_ledger: u64,
        cursor: Option<&str>,
    ) -> Result<()> {
        self.store.borrow_mut().sync_metadata.insert(
            contract_type.to_string(),
            SyncMetadata {
                last_ledger,
                last_cursor: cursor.map(String::from),
            },
        );
        self.save()
    }

    // ========== Pool leaves ==========

    /// Insert a pool leaf.
    pub fn insert_pool_leaf(&self, idx: u64, commitment: &str, ledger: u64) -> Result<()> {
        self.store
            .borrow_mut()
            .pool_leaves
            .entry(idx)
            .or_insert(PoolLeaf {
                commitment: commitment.to_string(),
                ledger,
            });
        self.save()
    }

    /// Get all pool leaves ordered by index.
    pub fn get_pool_leaves(&self) -> Result<Vec<(u64, String)>> {
        Ok(self
            .store
            .borrow()
            .pool_leaves
            .iter()
            .map(|(&idx, leaf)| (idx, leaf.commitment.clone()))
            .collect())
    }

    /// Count pool leaves.
    pub fn pool_leaf_count(&self) -> Result<u64> {
        Ok(self.store.borrow().pool_leaves.len() as u64)
    }

    // ========== Pool nullifiers ==========

    /// Insert a pool nullifier.
    pub fn insert_nullifier(&self, nullifier: &str, ledger: u64) -> Result<()> {
        self.store
            .borrow_mut()
            .nullifiers
            .entry(nullifier.to_string())
            .or_insert(ledger);
        self.save()
    }

    /// Check if a nullifier exists.
    pub fn has_nullifier(&self, nullifier: &str) -> Result<bool> {
        Ok(self.store.borrow().nullifiers.contains_key(nullifier))
    }

    /// Count nullifiers.
    pub fn nullifier_count(&self) -> Result<u64> {
        Ok(self.store.borrow().nullifiers.len() as u64)
    }

    // ========== Encrypted outputs ==========

    /// Insert an encrypted output.
    pub fn insert_encrypted_output(
        &self,
        commitment: &str,
        idx: u64,
        encrypted_output: &[u8],
        ledger: u64,
    ) -> Result<()> {
        self.store
            .borrow_mut()
            .encrypted_outputs
            .entry(idx)
            .or_insert(EncryptedOutputEntry {
                commitment: commitment.to_string(),
                encrypted_output: general_purpose::STANDARD.encode(encrypted_output),
                ledger,
            });
        self.save()
    }

    /// Get all encrypted outputs.
    pub fn get_encrypted_outputs(&self) -> Result<Vec<EncryptedOutput>> {
        self.store
            .borrow()
            .encrypted_outputs
            .iter()
            .map(|(&idx, entry)| {
                let bytes = general_purpose::STANDARD
                    .decode(&entry.encrypted_output)
                    .context("Failed to decode base64 encrypted output")?;
                Ok((entry.commitment.clone(), idx, bytes, entry.ledger))
            })
            .collect()
    }

    // ========== ASP membership leaves ==========

    /// Insert an ASP membership leaf.
    pub fn insert_asp_leaf(&self, idx: u64, leaf: &str, ledger: u64) -> Result<()> {
        self.store
            .borrow_mut()
            .asp_leaves
            .entry(idx)
            .or_insert(AspLeaf {
                leaf: leaf.to_string(),
                ledger,
            });
        self.save()
    }

    /// Get all ASP membership leaves.
    pub fn get_asp_leaves(&self) -> Result<Vec<(u64, String)>> {
        Ok(self
            .store
            .borrow()
            .asp_leaves
            .iter()
            .map(|(&idx, entry)| (idx, entry.leaf.clone()))
            .collect())
    }

    /// Count ASP leaves.
    pub fn asp_leaf_count(&self) -> Result<u64> {
        Ok(self.store.borrow().asp_leaves.len() as u64)
    }

    // ========== User notes ==========

    /// Insert or update a user note.
    pub fn upsert_note(&self, note: &UserNote) -> Result<()> {
        let mut store = self.store.borrow_mut();
        if let Some(existing) = store.user_notes.get_mut(&note.id) {
            existing.spent = note.spent;
        } else {
            store.user_notes.insert(note.id.clone(), note.clone());
        }
        drop(store);
        self.save()
    }

    /// Get a note by ID.
    pub fn get_note(&self, id: &str) -> Result<Option<UserNote>> {
        Ok(self.store.borrow().user_notes.get(id).cloned())
    }

    /// List all notes for a given owner.
    pub fn list_notes(&self, owner: &str) -> Result<Vec<UserNote>> {
        let mut notes: Vec<UserNote> = self
            .store
            .borrow()
            .user_notes
            .values()
            .filter(|n| n.owner == owner)
            .cloned()
            .collect();
        notes.sort_by_key(|n| n.leaf_index);
        Ok(notes)
    }

    /// List all unspent notes for a given owner.
    pub fn list_unspent_notes(&self, owner: &str) -> Result<Vec<UserNote>> {
        let mut notes: Vec<UserNote> = self
            .store
            .borrow()
            .user_notes
            .values()
            .filter(|n| n.owner == owner && n.spent == 0)
            .cloned()
            .collect();
        notes.sort_by_key(|n| n.leaf_index);
        Ok(notes)
    }

    /// Mark a note as spent.
    pub fn mark_note_spent(&self, id: &str) -> Result<()> {
        if let Some(note) = self.store.borrow_mut().user_notes.get_mut(id) {
            note.spent = 1;
        }
        self.save()
    }

    // ========== Registered public keys ==========

    /// Upsert a registered public key.
    pub fn upsert_public_key(&self, key: &RegisteredKey) -> Result<()> {
        self.store
            .borrow_mut()
            .registered_keys
            .insert(key.address.clone(), key.clone());
        self.save()
    }

    /// Get a registered public key by address.
    pub fn get_public_key(&self, address: &str) -> Result<Option<RegisteredKey>> {
        Ok(self.store.borrow().registered_keys.get(address).cloned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_in_memory().expect("in-memory DB")
    }

    // ========== Sync metadata ==========

    #[test]
    fn test_sync_metadata_default() {
        let db = test_db();
        assert_eq!(db.get_last_ledger("pool").unwrap(), 0);
        assert_eq!(db.get_last_cursor("pool").unwrap(), None);
    }

    #[test]
    fn test_sync_metadata_update() {
        let db = test_db();
        db.update_sync_metadata("pool", 100, Some("cursor_abc"))
            .unwrap();
        assert_eq!(db.get_last_ledger("pool").unwrap(), 100);
        assert_eq!(
            db.get_last_cursor("pool").unwrap(),
            Some("cursor_abc".to_string())
        );

        // Upsert
        db.update_sync_metadata("pool", 200, Some("cursor_def"))
            .unwrap();
        assert_eq!(db.get_last_ledger("pool").unwrap(), 200);
        assert_eq!(
            db.get_last_cursor("pool").unwrap(),
            Some("cursor_def".to_string())
        );
    }

    #[test]
    fn test_sync_metadata_multiple_contracts() {
        let db = test_db();
        db.update_sync_metadata("pool", 100, None).unwrap();
        db.update_sync_metadata("asp_membership", 50, Some("abc"))
            .unwrap();

        assert_eq!(db.get_last_ledger("pool").unwrap(), 100);
        assert_eq!(db.get_last_ledger("asp_membership").unwrap(), 50);
        assert_eq!(db.get_last_cursor("pool").unwrap(), None);
        assert_eq!(
            db.get_last_cursor("asp_membership").unwrap(),
            Some("abc".to_string())
        );
    }

    // ========== Pool leaves ==========

    #[test]
    fn test_pool_leaves() {
        let db = test_db();
        assert_eq!(db.pool_leaf_count().unwrap(), 0);
        assert!(db.get_pool_leaves().unwrap().is_empty());

        db.insert_pool_leaf(0, "aabb", 10).unwrap();
        db.insert_pool_leaf(5, "ccdd", 12).unwrap();

        assert_eq!(db.pool_leaf_count().unwrap(), 2);

        let leaves = db.get_pool_leaves().unwrap();
        assert_eq!(leaves, vec![(0, "aabb".to_string()), (5, "ccdd".to_string())]);
    }

    #[test]
    fn test_pool_leaf_insert_or_ignore() {
        let db = test_db();
        db.insert_pool_leaf(0, "aabb", 10).unwrap();
        // Duplicate index — should be ignored
        db.insert_pool_leaf(0, "aabb", 20).unwrap();
        assert_eq!(db.pool_leaf_count().unwrap(), 1);
    }

    // ========== Nullifiers ==========

    #[test]
    fn test_nullifiers() {
        let db = test_db();
        assert!(!db.has_nullifier("nul1").unwrap());
        assert_eq!(db.nullifier_count().unwrap(), 0);

        db.insert_nullifier("nul1", 5).unwrap();
        assert!(db.has_nullifier("nul1").unwrap());
        assert!(!db.has_nullifier("nul2").unwrap());
        assert_eq!(db.nullifier_count().unwrap(), 1);
    }

    // ========== Encrypted outputs ==========

    #[test]
    fn test_encrypted_outputs() {
        let db = test_db();
        let data1 = vec![1u8; 112];
        let data2 = vec![2u8; 112];
        db.insert_encrypted_output("cm1", 0, &data1, 10).unwrap();
        db.insert_encrypted_output("cm2", 1, &data2, 11).unwrap();

        let outputs = db.get_encrypted_outputs().unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].0, "cm1");
        assert_eq!(outputs[0].1, 0);
        assert_eq!(outputs[0].2, data1);
        assert_eq!(outputs[0].3, 10);
        assert_eq!(outputs[1].0, "cm2");
    }

    // ========== ASP membership leaves ==========

    #[test]
    fn test_asp_leaves() {
        let db = test_db();
        assert_eq!(db.asp_leaf_count().unwrap(), 0);

        db.insert_asp_leaf(0, "leaf0", 100).unwrap();
        db.insert_asp_leaf(3, "leaf3", 101).unwrap();

        assert_eq!(db.asp_leaf_count().unwrap(), 2);

        let leaves = db.get_asp_leaves().unwrap();
        assert_eq!(leaves, vec![(0, "leaf0".to_string()), (3, "leaf3".to_string())]);
    }

    // ========== User notes ==========

    fn make_note(id: &str, owner: &str, amount: u64) -> UserNote {
        UserNote {
            id: id.to_string(),
            owner: owner.to_string(),
            private_key: "pk_hex".to_string(),
            blinding: "bl_hex".to_string(),
            amount,
            leaf_index: 0,
            spent: 0,
            is_received: 0,
            ledger: Some(42),
        }
    }

    #[test]
    fn test_user_note_upsert_and_get() {
        let db = test_db();
        let note = make_note("cm_abc", "owner1", 1000);
        db.upsert_note(&note).unwrap();

        let fetched = db.get_note("cm_abc").unwrap().expect("note should exist");
        assert_eq!(fetched.id, "cm_abc");
        assert_eq!(fetched.owner, "owner1");
        assert_eq!(fetched.amount, 1000);
        assert_eq!(fetched.spent, 0);
    }

    #[test]
    fn test_user_note_not_found() {
        let db = test_db();
        assert!(db.get_note("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_user_note_upsert_updates_spent() {
        let db = test_db();
        let mut note = make_note("cm1", "owner1", 500);
        db.upsert_note(&note).unwrap();

        note.spent = 1;
        db.upsert_note(&note).unwrap();

        let fetched = db.get_note("cm1").unwrap().unwrap();
        assert_eq!(fetched.spent, 1);
    }

    #[test]
    fn test_list_notes() {
        let db = test_db();
        let mut n1 = make_note("cm1", "ownerA", 100);
        n1.leaf_index = 0;
        let mut n2 = make_note("cm2", "ownerA", 200);
        n2.leaf_index = 1;
        let mut n3 = make_note("cm3", "ownerB", 300);
        n3.leaf_index = 2;

        db.upsert_note(&n1).unwrap();
        db.upsert_note(&n2).unwrap();
        db.upsert_note(&n3).unwrap();

        let owner_a = db.list_notes("ownerA").unwrap();
        assert_eq!(owner_a.len(), 2);
        assert_eq!(owner_a[0].amount, 100);
        assert_eq!(owner_a[1].amount, 200);

        let owner_b = db.list_notes("ownerB").unwrap();
        assert_eq!(owner_b.len(), 1);
    }

    #[test]
    fn test_list_unspent_notes() {
        let db = test_db();
        let mut n1 = make_note("cm1", "ownerA", 100);
        n1.leaf_index = 0;
        let mut n2 = make_note("cm2", "ownerA", 200);
        n2.leaf_index = 1;
        n2.spent = 1;

        db.upsert_note(&n1).unwrap();
        db.upsert_note(&n2).unwrap();

        let unspent = db.list_unspent_notes("ownerA").unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].amount, 100);
    }

    #[test]
    fn test_mark_note_spent() {
        let db = test_db();
        let note = make_note("cm1", "ownerA", 500);
        db.upsert_note(&note).unwrap();

        db.mark_note_spent("cm1").unwrap();

        let fetched = db.get_note("cm1").unwrap().unwrap();
        assert_eq!(fetched.spent, 1);
    }

    // ========== Registered public keys ==========

    #[test]
    fn test_public_key_upsert_and_get() {
        let db = test_db();
        let key = RegisteredKey {
            address: "GABC".to_string(),
            note_key: "nk_hex".to_string(),
            encryption_key: "ek_hex".to_string(),
            ledger: 99,
        };
        db.upsert_public_key(&key).unwrap();

        let fetched = db.get_public_key("GABC").unwrap().expect("key should exist");
        assert_eq!(fetched.note_key, "nk_hex");
        assert_eq!(fetched.encryption_key, "ek_hex");
        assert_eq!(fetched.ledger, 99);
    }

    #[test]
    fn test_public_key_not_found() {
        let db = test_db();
        assert!(db.get_public_key("GNONE").unwrap().is_none());
    }

    #[test]
    fn test_public_key_upsert_overwrites() {
        let db = test_db();
        let key1 = RegisteredKey {
            address: "GABC".to_string(),
            note_key: "old".to_string(),
            encryption_key: "old_ek".to_string(),
            ledger: 1,
        };
        db.upsert_public_key(&key1).unwrap();

        let key2 = RegisteredKey {
            address: "GABC".to_string(),
            note_key: "new".to_string(),
            encryption_key: "new_ek".to_string(),
            ledger: 2,
        };
        db.upsert_public_key(&key2).unwrap();

        let fetched = db.get_public_key("GABC").unwrap().unwrap();
        assert_eq!(fetched.note_key, "new");
        assert_eq!(fetched.ledger, 2);
    }
}

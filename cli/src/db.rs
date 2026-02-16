//! SQLite schema, migrations, queries.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::PathBuf;

/// An encrypted output entry: (commitment_hex, leaf_index, encrypted_data, ledger).
pub type EncryptedOutput = (String, u64, Vec<u8>, u64);

/// A user note stored in the database.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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

/// Database path for a given network.
pub fn db_path(network: &str) -> Result<PathBuf> {
    let base = dirs::config_dir().context("Could not determine config directory")?;
    Ok(base.join("stellar").join("spp").join(format!("{network}.db")))
}

/// SQLite database wrapper.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) the database for the given network.
    pub fn open(network: &str) -> Result<Self> {
        let path = db_path(network)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create db dir {}", parent.display()))?;
        }
        let conn = Connection::open(&path)
            .with_context(|| format!("Failed to open database at {}", path.display()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .context("Failed to set pragmas")?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Failed to open in-memory database")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .context("Failed to set pragmas")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Run schema migrations.
    pub fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_metadata (
                contract_type TEXT PRIMARY KEY,
                last_ledger INTEGER DEFAULT 0,
                last_cursor TEXT,
                sync_broken INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pool_leaves (
                idx INTEGER PRIMARY KEY,
                commitment TEXT NOT NULL UNIQUE,
                ledger INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pool_nullifiers (
                nullifier TEXT PRIMARY KEY,
                ledger INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pool_encrypted_outputs (
                commitment TEXT PRIMARY KEY,
                idx INTEGER NOT NULL,
                encrypted_output BLOB NOT NULL,
                ledger INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asp_membership_leaves (
                idx INTEGER PRIMARY KEY,
                leaf TEXT NOT NULL,
                ledger INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_notes (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                private_key TEXT NOT NULL,
                blinding TEXT NOT NULL,
                amount INTEGER NOT NULL,
                leaf_index INTEGER NOT NULL,
                spent INTEGER DEFAULT 0,
                is_received INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                ledger INTEGER
            );

            CREATE TABLE IF NOT EXISTS registered_public_keys (
                address TEXT PRIMARY KEY,
                note_key TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                ledger INTEGER NOT NULL
            );
            ",
            )
            .context("Failed to run migrations")?;
        Ok(())
    }

    // ========== Sync metadata ==========

    /// Get the last synced ledger for a contract type.
    pub fn get_last_ledger(&self, contract_type: &str) -> Result<u64> {
        let result: Result<u64, _> = self.conn.query_row(
            "SELECT last_ledger FROM sync_metadata WHERE contract_type = ?1",
            params![contract_type],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the last cursor for a contract type.
    pub fn get_last_cursor(&self, contract_type: &str) -> Result<Option<String>> {
        let result: Result<Option<String>, _> = self.conn.query_row(
            "SELECT last_cursor FROM sync_metadata WHERE contract_type = ?1",
            params![contract_type],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update sync metadata.
    pub fn update_sync_metadata(
        &self,
        contract_type: &str,
        last_ledger: u64,
        cursor: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_metadata (contract_type, last_ledger, last_cursor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(contract_type)
             DO UPDATE SET last_ledger = ?2, last_cursor = ?3",
            params![contract_type, last_ledger, cursor],
        )?;
        Ok(())
    }

    // ========== Pool leaves ==========

    /// Insert a pool leaf.
    pub fn insert_pool_leaf(&self, idx: u64, commitment: &str, ledger: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pool_leaves (idx, commitment, ledger) VALUES (?1, ?2, ?3)",
            params![idx, commitment, ledger],
        )?;
        Ok(())
    }

    /// Get all pool leaves ordered by index.
    pub fn get_pool_leaves(&self) -> Result<Vec<(u64, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT idx, commitment FROM pool_leaves ORDER BY idx")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Count pool leaves.
    pub fn pool_leaf_count(&self) -> Result<u64> {
        let count: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pool_leaves", [], |row| row.get(0))?;
        Ok(count)
    }

    // ========== Pool nullifiers ==========

    /// Insert a pool nullifier.
    pub fn insert_nullifier(&self, nullifier: &str, ledger: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pool_nullifiers (nullifier, ledger) VALUES (?1, ?2)",
            params![nullifier, ledger],
        )?;
        Ok(())
    }

    /// Check if a nullifier exists.
    pub fn has_nullifier(&self, nullifier: &str) -> Result<bool> {
        let count: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pool_nullifiers WHERE nullifier = ?1",
            params![nullifier],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Count nullifiers.
    pub fn nullifier_count(&self) -> Result<u64> {
        let count: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pool_nullifiers", [], |row| row.get(0))?;
        Ok(count)
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
        self.conn.execute(
            "INSERT OR IGNORE INTO pool_encrypted_outputs (commitment, idx, encrypted_output, ledger)
             VALUES (?1, ?2, ?3, ?4)",
            params![commitment, idx, encrypted_output, ledger],
        )?;
        Ok(())
    }

    /// Get all encrypted outputs.
    pub fn get_encrypted_outputs(&self) -> Result<Vec<EncryptedOutput>> {
        let mut stmt = self.conn.prepare(
            "SELECT commitment, idx, encrypted_output, ledger FROM pool_encrypted_outputs ORDER BY idx",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // ========== ASP membership leaves ==========

    /// Insert an ASP membership leaf.
    pub fn insert_asp_leaf(&self, idx: u64, leaf: &str, ledger: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO asp_membership_leaves (idx, leaf, ledger) VALUES (?1, ?2, ?3)",
            params![idx, leaf, ledger],
        )?;
        Ok(())
    }

    /// Get all ASP membership leaves.
    pub fn get_asp_leaves(&self) -> Result<Vec<(u64, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT idx, leaf FROM asp_membership_leaves ORDER BY idx")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Count ASP leaves.
    pub fn asp_leaf_count(&self) -> Result<u64> {
        let count: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM asp_membership_leaves",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // ========== User notes ==========

    /// Insert or update a user note.
    pub fn upsert_note(&self, note: &UserNote) -> Result<()> {
        self.conn.execute(
            "INSERT INTO user_notes (id, owner, private_key, blinding, amount, leaf_index, spent, is_received, ledger)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id)
             DO UPDATE SET spent = ?7",
            params![
                note.id,
                note.owner,
                note.private_key,
                note.blinding,
                note.amount,
                note.leaf_index,
                note.spent,
                note.is_received,
                note.ledger,
            ],
        )?;
        Ok(())
    }

    /// Get a note by ID.
    pub fn get_note(&self, id: &str) -> Result<Option<UserNote>> {
        let result = self.conn.query_row(
            "SELECT id, owner, private_key, blinding, amount, leaf_index, spent, is_received, ledger
             FROM user_notes WHERE id = ?1",
            params![id],
            |row| {
                Ok(UserNote {
                    id: row.get(0)?,
                    owner: row.get(1)?,
                    private_key: row.get(2)?,
                    blinding: row.get(3)?,
                    amount: row.get(4)?,
                    leaf_index: row.get(5)?,
                    spent: row.get(6)?,
                    is_received: row.get(7)?,
                    ledger: row.get(8)?,
                })
            },
        );
        match result {
            Ok(n) => Ok(Some(n)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all notes for a given owner.
    pub fn list_notes(&self, owner: &str) -> Result<Vec<UserNote>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, owner, private_key, blinding, amount, leaf_index, spent, is_received, ledger
             FROM user_notes WHERE owner = ?1 ORDER BY leaf_index",
        )?;
        let rows = stmt.query_map(params![owner], |row| {
            Ok(UserNote {
                id: row.get(0)?,
                owner: row.get(1)?,
                private_key: row.get(2)?,
                blinding: row.get(3)?,
                amount: row.get(4)?,
                leaf_index: row.get(5)?,
                spent: row.get(6)?,
                is_received: row.get(7)?,
                ledger: row.get(8)?,
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// List all unspent notes for a given owner.
    pub fn list_unspent_notes(&self, owner: &str) -> Result<Vec<UserNote>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, owner, private_key, blinding, amount, leaf_index, spent, is_received, ledger
             FROM user_notes WHERE owner = ?1 AND spent = 0 ORDER BY leaf_index",
        )?;
        let rows = stmt.query_map(params![owner], |row| {
            Ok(UserNote {
                id: row.get(0)?,
                owner: row.get(1)?,
                private_key: row.get(2)?,
                blinding: row.get(3)?,
                amount: row.get(4)?,
                leaf_index: row.get(5)?,
                spent: row.get(6)?,
                is_received: row.get(7)?,
                ledger: row.get(8)?,
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Mark a note as spent.
    pub fn mark_note_spent(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE user_notes SET spent = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    // ========== Registered public keys ==========

    /// Upsert a registered public key.
    pub fn upsert_public_key(&self, key: &RegisteredKey) -> Result<()> {
        self.conn.execute(
            "INSERT INTO registered_public_keys (address, note_key, encryption_key, ledger)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(address)
             DO UPDATE SET note_key = ?2, encryption_key = ?3, ledger = ?4",
            params![key.address, key.note_key, key.encryption_key, key.ledger],
        )?;
        Ok(())
    }

    /// Get a registered public key by address.
    pub fn get_public_key(&self, address: &str) -> Result<Option<RegisteredKey>> {
        let result = self.conn.query_row(
            "SELECT address, note_key, encryption_key, ledger FROM registered_public_keys WHERE address = ?1",
            params![address],
            |row| {
                Ok(RegisteredKey {
                    address: row.get(0)?,
                    note_key: row.get(1)?,
                    encryption_key: row.get(2)?,
                    ledger: row.get(3)?,
                })
            },
        );
        match result {
            Ok(k) => Ok(Some(k)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a reference to the underlying connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
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

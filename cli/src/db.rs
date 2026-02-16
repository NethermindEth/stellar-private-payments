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

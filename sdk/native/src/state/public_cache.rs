//! Public chain cache, usable without opening the private vault.
//!
//! The vault retains its own chain snapshot so private foreign keys remain
//! local and a crash never requires an atomic commit across two files. Only
//! raw chain events and sync progress cross this boundary; derived rows are
//! rebuilt with each database's own IDs. Private tables are never copied.
use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use super::Storage;

impl Storage {
    /// Open a cache containing public chain data and ordinary app settings.
    /// This does not create private tables or require an encryption key.
    pub fn connect_public(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        #[cfg(not(target_arch = "wasm32"))]
        let absolute = if path == Path::new(":memory:") {
            path.to_path_buf()
        } else {
            std::path::absolute(path)?
        };
        #[cfg(not(target_arch = "wasm32"))]
        let path = absolute.as_path();
        #[cfg(not(target_arch = "wasm32"))]
        if path.exists() && std::fs::metadata(path)?.len() > 0 {
            super::database_key::validate_read_only(path, None)?;
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("schema_public.sql"))?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }
        ensure!(version <= 1, "unsupported public cache version");
        // Refuse an accidentally supplied vault or legacy database path.
        let _: i64 = conn.query_row("SELECT count(*) FROM cache_metadata", [], |r| r.get(0))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self {
            conn,
            public_only: true,
        })
    }

    pub fn is_public_only(&self) -> bool {
        self.public_only
    }

    pub fn is_public_setting(key: &str) -> bool {
        matches!(key, "explorer" | "bootnode_config")
    }

    pub(super) fn check_setting_access(&self, key: &str) -> Result<()> {
        ensure!(
            !self.public_only || Self::is_public_setting(key),
            "unlock private data first"
        );
        Ok(())
    }

    /// Copy the vault's public history into the cache once, then bring the
    /// vault up to the cache's latest progress on every unlock. A committed
    /// marker makes interrupted migration retryable and prevents old vault
    /// cursors from undoing a later RPC handoff in the public cache.
    pub fn synchronize_public_cache(&mut self, cache: &mut Self) -> Result<()> {
        ensure!(
            !self.public_only && cache.public_only,
            "expected a vault and public cache"
        );
        let seeded: bool = cache.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cache_metadata WHERE key='vault_seeded')",
            [],
            |r| r.get(0),
        )?;
        if !seeded {
            cache.copy_chain_from(self, true)?;
            for key in ["explorer", "bootnode_config"] {
                if cache.get_setting_json::<serde_json::Value>(key)?.is_none()
                    && let Some(value) = self.get_setting_json::<serde_json::Value>(key)?
                {
                    cache.set_setting_json(key, &value)?;
                }
            }
            cache
                .conn
                .execute("INSERT INTO cache_metadata VALUES ('vault_seeded','1')", [])?;
        }
        self.copy_chain_from(cache, false)
    }

    fn copy_chain_from(&mut self, source: &Self, merge_progress: bool) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut events = source.conn.prepare(
            "SELECT r.id,r.ledger,c.address,r.topics,r.value FROM raw_contract_events r
             JOIN contracts c ON c.contract_id=r.contract_id ORDER BY r.ledger,r.id",
        )?;
        let mut rows = events.query([])?;
        while let Some(row) = rows.next()? {
            let address: String = row.get(2)?;
            tx.execute(
                "INSERT OR IGNORE INTO contracts(address) VALUES (?1)",
                [&address],
            )?;
            let contract: i64 = tx.query_row(
                "SELECT contract_id FROM contracts WHERE address=?1",
                [&address],
                |r| r.get(0),
            )?;
            let id: String = row.get(0)?;
            let ledger: i64 = row.get(1)?;
            let topics: String = row.get(3)?;
            let value: String = row.get(4)?;
            tx.execute(
                "INSERT INTO raw_contract_events(id,ledger,contract_id,topics,value) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(id) DO NOTHING",
                params![id, ledger, contract, topics, value],
            )?;
            let matches: bool = tx.query_row(
                "SELECT ledger=?2 AND contract_id=?3 AND topics=?4 AND value=?5 FROM raw_contract_events WHERE id=?1",
                params![id, ledger, contract, topics, value], |r| r.get(0),
            )?;
            ensure!(matches, "public cache conflicts with a stored chain event");
        }
        // Progress commits in the same transaction as the events it covers.
        for m in source.get_sync_metadata()? {
            tx.execute(
                "INSERT OR IGNORE INTO contracts(address) VALUES (?1)",
                [&m.contract_id],
            )?;
            let contract: i64 = tx.query_row(
                "SELECT contract_id FROM contracts WHERE address=?1",
                [&m.contract_id],
                |r| r.get(0),
            )?;
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT last_indexed_ledger FROM indexing_metadata WHERE contract_id=?1",
                    [contract],
                    |r| r.get(0),
                )
                .optional()?;
            if merge_progress
                && existing.is_some_and(|ledger| ledger >= i64::from(m.last_indexed_ledger))
            {
                continue;
            }
            tx.execute(
                "INSERT INTO indexing_metadata VALUES (?1,?2,?3,?4) ON CONFLICT(contract_id) DO UPDATE SET last_cursor=excluded.last_cursor,last_indexed_ledger=excluded.last_indexed_ledger,last_fully_indexed_ledger=excluded.last_fully_indexed_ledger",
                params![contract, m.cursor, m.last_indexed_ledger, m.last_fully_indexed_ledger],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "public_cache_tests.rs"]
mod tests;

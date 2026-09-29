//! Public chain storage and a private-only encrypted attachment.
//! Stable commitment hashes and pool addresses permit joins without copies
//! of chain events, derived public tables or indexer progress in the vault.
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
        ensure!(version <= 2, "unsupported public cache version");
        // Refuse an accidentally supplied vault or legacy database path.
        let _: i64 = conn.query_row("SELECT count(*) FROM cache_metadata", [], |r| r.get(0))?;
        if version < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch("CREATE INDEX IF NOT EXISTS idx_pool_commitments_leaf_index ON pool_commitments(leaf_index)")?;
            tx.pragma_update(None, "user_version", 2)?;
            tx.commit()?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self {
            conn,
            public_only: true,
            private_attached: false,
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

    pub(super) fn setting_table(&self, key: &str) -> &'static str {
        if self.private_attached && !Self::is_public_setting(key) {
            "vault.private_settings"
        } else {
            "app_settings"
        }
    }

    /// One-time upgrade of a complete encrypted wallet to a private-only
    /// vault. Public events/progress commit first; private tables then drop
    /// their duplicate public state in a separate transaction. Either failure
    /// can be retried without losing the only copy of a record.
    pub fn migrate_private_vault(&mut self, vault: &mut Self) -> Result<()> {
        ensure!(
            self.public_only && !vault.public_only,
            "expected public storage and private vault"
        );
        let legacy: bool = vault.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='contracts')",
            [],
            |r| r.get(0),
        )?;
        if !legacy {
            return Ok(());
        }
        self.import_legacy_chain(vault)?;
        for key in ["explorer", "bootnode_config"] {
            if self.get_setting_json::<serde_json::Value>(key)?.is_none()
                && let Some(value) = vault.get_setting_json::<serde_json::Value>(key)?
            {
                self.set_setting_json(key, &value)?;
            }
        }
        let tx = vault.conn.transaction()?;
        tx.execute_batch(
            "DELETE FROM app_settings WHERE key IN ('explorer','bootnode_config');
             ALTER TABLE app_settings RENAME TO private_settings;
             DROP TABLE pool_commitments;
             DROP TABLE pool_nullifiers;
             DROP TABLE public_keys;
             DROP TABLE asp_membership_leaves;
             DROP TABLE indexing_metadata;
             DROP TABLE raw_contract_events;
             DROP TABLE contracts;",
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Attach the authenticated private-only vault. The public database is
    /// main; only private tables are in vault, so unqualified joins can read
    /// both schemas without copying or opening a second public handle.
    pub fn attach_private_vault(
        &mut self,
        path: impl AsRef<Path>,
        key: &super::database_key::DatabaseKey,
    ) -> Result<()> {
        ensure!(
            self.public_only && !self.private_attached,
            "private vault already attached"
        );
        super::database_key::attach(&self.conn, path.as_ref(), key)?;
        let valid: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault.sqlite_schema WHERE name='private_settings')
             AND NOT EXISTS(SELECT 1 FROM vault.sqlite_schema WHERE name IN ('contracts','raw_contract_events','pool_commitments','pool_nullifiers','public_keys','asp_membership_leaves','indexing_metadata'))",
            [], |r| r.get(0),
        )?;
        if !valid {
            self.conn.execute_batch("DETACH DATABASE vault")?;
            anyhow::bail!("expected a private-only vault");
        }
        self.private_attached = true;
        self.public_only = false;
        Ok(())
    }

    fn import_legacy_chain(&mut self, source: &Self) -> Result<()> {
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
            if existing.is_some_and(|ledger| ledger >= i64::from(m.last_indexed_ledger)) {
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

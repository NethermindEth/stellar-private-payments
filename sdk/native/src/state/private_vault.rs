//! Private-only encrypted storage has its own format and migration history.
use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use rusqlite_migration::{M, Migrations};

use super::{
    Storage,
    database_key::{self, DatabaseKey, OpenPurpose},
};

pub(super) const APPLICATION_ID: i32 = 0x5350_5056; // SPPV
const PRIVATE_SCHEMA: &[M] = &[M::up(include_str!("schema_private.sql"))];
const MIGRATIONS: Migrations = Migrations::from_slice(PRIVATE_SCHEMA);
// Frozen conversion of historical complete vaults, never the latest native
// migrations. Future native/public changes must not run against private files.
const LEGACY_SCHEMA: &[M] = &[
    M::up(include_str!("schema.sql")),
    M::up(include_str!("schema_v2_gvk_ciphertext.sql")),
    M::up(include_str!("schema_v3_private_references.sql")),
];
const LEGACY_MIGRATIONS: Migrations = Migrations::from_slice(LEGACY_SCHEMA);

pub(super) fn is_private(conn: &Connection) -> Result<bool> {
    let application: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    Ok(application == APPLICATION_ID || has_table(conn, "private_settings")?)
}

fn has_table(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}

impl Storage {
    /// Create or unlock a private vault, upgrade historical layouts once, then
    /// attach it to this public connection. Native database migrations are
    /// never applied to private-only files.
    pub fn open_private_vault(
        &mut self,
        path: impl AsRef<Path>,
        key: &DatabaseKey,
        purpose: OpenPurpose,
    ) -> Result<()> {
        ensure!(
            self.public_only && !self.private_attached,
            "private vault already attached"
        );
        let path = path.as_ref();
        let mut vault = database_key::open(path, key, purpose)?;
        let application: i32 = vault.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = vault.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let complete = has_table(&vault, "contracts")?;
        let private = has_table(&vault, "private_settings")?;
        let public_tables: bool = vault.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name IN
             ('contracts','raw_contract_events','pool_commitments','pool_nullifiers',
              'public_keys','asp_membership_leaves','indexing_metadata'))",
            [],
            |r| r.get(0),
        )?;
        if application == APPLICATION_ID {
            ensure!(
                !public_tables && private && version > 0,
                "invalid private vault layout"
            );
        } else {
            ensure!(application == 0, "unsupported vault format");
            if complete {
                ensure!(
                    !private && (1..=3).contains(&version),
                    "unsupported legacy vault version"
                );
                LEGACY_MIGRATIONS.to_latest(&mut vault)?;
                super::encrypted_migration::check_integrity(&vault)?;
                self.convert_legacy_vault(&mut vault)?;
            } else {
                let count: i64 =
                    vault.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
                ensure!(
                    purpose == OpenPurpose::CreateNew && version == 0 && count == 0,
                    "unrecognized private vault layout"
                );
            }
        }
        MIGRATIONS.to_latest(&mut vault)?;
        vault.pragma_update(None, "foreign_keys", "ON")?;
        // The SAH VFS permits one handle per filename. Close the standalone
        // handle before attaching; all queries subsequently use public main.
        drop(vault);
        database_key::attach(&self.conn, path, key)?;
        self.private_attached = true;
        self.public_only = false;
        Ok(())
    }

    fn convert_legacy_vault(&mut self, vault: &mut Connection) -> Result<()> {
        // Commit the public export first. A failure/interruption leaves the
        // vault's public rows in place and the conversion can be retried.
        self.import_legacy_chain(vault)?;
        for key in ["explorer", "bootnode_config"] {
            if self.get_setting_json::<serde_json::Value>(key)?.is_none() {
                let value: Option<String> = vault
                    .query_row("SELECT value FROM app_settings WHERE key=?1", [key], |r| {
                        r.get(0)
                    })
                    .optional()?;
                if let Some(value) = value {
                    self.set_setting_json(
                        key,
                        &serde_json::from_str::<serde_json::Value>(&value)?,
                    )?;
                }
            }
        }
        let tx = vault.transaction()?;
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
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        Ok(())
    }
}

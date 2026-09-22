//! Explicit migration building blocks; these never run during ordinary opens.
//!
//! The native coordinator is available on Linux. The logical copy primitive is
//! shared with WASM, where OPFS ownership/activation must be coordinated
//! separately.

use anyhow::{Result, ensure};
use rusqlite::{Connection, params_from_iter, types::ValueRef};
use sha2::{Digest, Sha256};

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::{MigrationStatus, NativeMigration};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

type Schema = Vec<(String, String, Option<String>)>;

/// Authenticate an initialization-only directory entry without exposing the
/// source digest. Persist it before any control write, and retire it durably
/// before exposing a coordinator that can create a candidate. Its presence
/// authorizes explicit recovery of incomplete control files, never user data.
pub fn initialization_marker(
    key: &super::database_key::DatabaseKey,
    platform: &str,
    source_binding: &[u8],
) -> String {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2_010::Sha256>::new_from_slice(key.as_ref()).expect("HMAC accepts a 32-byte key");
    mac.update(b"spp/database-migration/setup/v1\0");
    mac.update(platform.as_bytes());
    mac.update(&[0]);
    mac.update(source_binding);
    format!(".setup-v1-{}", hex::encode(mac.finalize().into_bytes()))
}

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn schema(conn: &Connection) -> Result<Schema> {
    Ok(conn
        .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

fn tables(conn: &Connection) -> Result<Vec<(String, bool)>> {
    let tables: Vec<(String, String, bool)> = conn.prepare(
        "SELECT name,type,wr FROM pragma_table_list WHERE schema='main' AND name<>'sqlite_schema' ORDER BY name",
    )?.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
    let mut result = Vec::new();
    for (name, kind, without_rowid) in tables {
        if kind == "view" {
            continue;
        }
        ensure!(
            kind == "table",
            "migration does not support virtual or shadow tables"
        );
        let hidden: i64 = conn.query_row(
            "SELECT count(*) FROM pragma_table_xinfo(?1) WHERE hidden<>0 OR lower(name)='rowid'",
            [&name],
            |r| r.get(0),
        )?;
        ensure!(
            hidden == 0,
            "migration does not support generated or rowid-shadowing columns"
        );
        result.push((name, without_rowid));
    }
    result.sort_by_key(|(name, _)| name == "sqlite_sequence");
    Ok(result)
}

fn check_integrity(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare("PRAGMA integrity_check")?;
    let messages = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(messages == ["ok"], "database integrity check failed");
    ensure!(
        conn.prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none(),
        "database foreign key check failed"
    );
    Ok(())
}

/// A digest of schema, exact typed values (including rowids), and version
/// headers. Keep it private to the encrypted control database; it is not a
/// public identifier.
pub fn fingerprint(conn: &Connection) -> Result<String> {
    check_integrity(conn)?;
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(&schema(conn)?)?);
    for pragma in ["user_version", "application_id"] {
        let value: i64 = conn.pragma_query_value(None, pragma, |r| r.get(0))?;
        hash.update(value.to_le_bytes());
    }
    for (table, without_rowid) in tables(conn)? {
        hash.update(u64::try_from(table.len())?.to_le_bytes());
        hash.update(table.as_bytes());
        let projection = if without_rowid { "*" } else { "rowid,*" };
        let mut statement = conn.prepare(&format!("SELECT {projection} FROM {}", ident(&table)))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        while let Some(row) = rows.next()? {
            let mut item = Sha256::new();
            for column in 0..columns {
                match row.get_ref(column)? {
                    ValueRef::Null => item.update([0]),
                    ValueRef::Integer(n) => {
                        item.update([1]);
                        item.update(n.to_le_bytes());
                    }
                    ValueRef::Real(n) => {
                        item.update([2]);
                        item.update(n.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                        item.update([if matches!(row.get_ref(column)?, ValueRef::Text(_)) {
                            3
                        } else {
                            4
                        }]);
                        item.update(u64::try_from(bytes.len())?.to_le_bytes());
                        item.update(bytes);
                    }
                }
            }
            hashes.push(item.finalize().into());
        }
        hashes.sort_unstable();
        hash.update(u64::try_from(hashes.len())?.to_le_bytes());
        for item in hashes {
            hash.update(item);
        }
    }
    Ok(hex::encode(hash.finalize()))
}

/// Copy into an empty connection which the caller has already keyed with
/// SQLite3MC. Both connections must be exclusively owned and outside
/// transactions. This copies SQL/data, not encrypted pages: schema and row
/// contents are checked before applying the SDK's ordinary migrations to the
/// destination only. No plaintext file, backup, dump or SQL log is produced.
/// The source is read-only.
pub fn copy_plaintext(source: &mut Connection, destination: &mut Connection) -> Result<()> {
    ensure!(
        schema(destination)?.is_empty(),
        "migration destination is not empty"
    );
    destination.pragma_update(None, "temp_store", "MEMORY")?;
    destination.pragma_update(None, "foreign_keys", "OFF")?;
    let source = source.transaction()?;
    let before = fingerprint(&source)?;
    let ddl = schema(&source)?;
    let tables = tables(&source)?;
    {
        let tx = destination.transaction()?;
        for (kind, name, sql) in &ddl {
            if kind == "table" && !name.starts_with("sqlite_") {
                tx.execute_batch(
                    sql.as_deref()
                        .ok_or_else(|| anyhow::anyhow!("missing table SQL"))?,
                )?;
            }
        }
        for (name, without_rowid) in tables {
            // sqlite_sequence is created automatically by AUTOINCREMENT DDL.
            ensure!(
                !name.starts_with("sqlite_") || name == "sqlite_sequence",
                "unsupported SQLite internal table"
            );
            let columns: Vec<String> = source
                .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?
                .query_map([&name], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut columns: Vec<String> = columns.iter().map(|name| ident(name)).collect();
            if !without_rowid {
                columns.insert(0, "rowid".into());
            }
            let projection = columns.join(",");
            if name == "sqlite_sequence" {
                tx.execute_batch("DELETE FROM sqlite_sequence")?;
            }
            let mut select =
                source.prepare(&format!("SELECT {projection} FROM {}", ident(&name)))?;
            let placeholders = vec!["?"; columns.len()].join(",");
            let mut insert = tx.prepare(&format!(
                "INSERT INTO {} ({projection}) VALUES ({placeholders})",
                ident(&name)
            ))?;
            let mut rows = select.query([])?;
            while let Some(row) = rows.next()? {
                let values = (0..columns.len())
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                insert.execute(params_from_iter(values.iter()))?;
                #[cfg(all(test, not(target_arch = "wasm32")))]
                if name == "keypairs" {
                    native::checkpoint("copy-in-progress");
                }
            }
        }
        // Triggers are installed after copying rows so they cannot run twice.
        for (kind, name, sql) in &ddl {
            if kind != "table"
                && !name.starts_with("sqlite_")
                && let Some(sql) = sql
            {
                tx.execute_batch(sql)?;
            }
        }
        for pragma in ["user_version", "application_id"] {
            let value: i64 = source.pragma_query_value(None, pragma, |r| r.get(0))?;
            tx.pragma_update(None, pragma, value)?;
        }
        ensure!(
            fingerprint(&tx)? == before,
            "migration copy differs from source"
        );
        tx.commit()?;
    }
    source.commit()?;
    super::storage::Storage::migrate_connection(destination)?;
    check_integrity(destination)
}

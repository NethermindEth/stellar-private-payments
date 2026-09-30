//! Moving an existing plaintext database into encrypted storage.
//!
//! [`copy_plaintext`] copies schema and rows into an empty encrypted
//! connection and checks the copy against the source before committing it.
//! Natively, [`encrypt_in_place`] wraps it: the copy goes into a new file that
//! then replaces the plaintext database with a rename.

use anyhow::{Result, ensure};
use rusqlite::{Connection, params_from_iter, types::ValueRef};
use sha2::{Digest, Sha256};

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "encrypted_migration_tests.rs"]
mod tests;

type Schema = Vec<(String, String, Option<String>)>;

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

// Optimizer statistics are derived, not application data. Exclude them from
// both copying and fingerprinting; SQLite can regenerate them with ANALYZE.
fn schema(conn: &Connection) -> Result<Schema> {
    Ok(conn
        .prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT IN ('sqlite_stat1','sqlite_stat2','sqlite_stat3','sqlite_stat4') ORDER BY type,name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

fn tables(conn: &Connection) -> Result<Vec<(String, bool)>> {
    let tables: Vec<(String, String, bool)> = conn
        .prepare(
            "SELECT name,type,wr FROM pragma_table_list WHERE schema='main' AND \
             name NOT IN ('sqlite_schema','sqlite_stat1','sqlite_stat2','sqlite_stat3','sqlite_stat4') ORDER BY name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
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

pub(super) fn check_integrity(conn: &Connection) -> Result<()> {
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

/// A digest of the schema, every typed value (including rowids) and the
/// version headers, used to check that a copy matches its source.
fn fingerprint(conn: &Connection) -> Result<String> {
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
                    ValueRef::Text(bytes) => {
                        item.update([3]);
                        item.update(u64::try_from(bytes.len())?.to_le_bytes());
                        item.update(bytes);
                    }
                    ValueRef::Blob(bytes) => {
                        item.update([4]);
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

/// Copy a plaintext database into an empty connection that the caller has
/// already keyed with SQLite3MC, preserving its schema version. The native
/// database and browser vault owners apply their own migrations afterwards.
///
/// Both connections must be owned exclusively and outside transactions. Rows
/// are copied as SQL values, never as pages, and the copy must match the
/// source before it is committed. The source is only read.
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
            // sqlite_sequence is created by the AUTOINCREMENT tables' DDL.
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
            }
        }
        // Indexes and triggers go in after the rows, so triggers cannot fire
        // during the copy.
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
    check_integrity(destination)
}

/// Copy the plaintext database at `source`, opened through the SQLite VFS
/// `source_vfs` (or the default one), into a new encrypted database at
/// `destination`, which must not exist yet.
pub fn copy_into_encrypted(
    source: &std::path::Path,
    source_vfs: Option<&str>,
    destination: &std::path::Path,
    key: &super::database_key::DatabaseKey,
) -> Result<()> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    // Opening normally rolls back a hot journal a crash may have left.
    let mut source = match source_vfs {
        Some(vfs) => Connection::open_with_flags_and_vfs(source, flags, vfs)?,
        None => Connection::open_with_flags(source, flags)?,
    };
    let mut destination = super::database_key::open(
        destination,
        key,
        super::database_key::OpenPurpose::CreateNew,
    )?;
    copy_plaintext(&mut source, &mut destination)
}

/// Whether the encrypted database at `path` has any tables. A copy commits
/// schema and rows together, so a database without tables, or without any
/// pages at all, holds an interrupted copy or creation and can be replaced.
pub fn has_tables(path: &std::path::Path, key: &super::database_key::DatabaseKey) -> Result<bool> {
    use rusqlite::OpenFlags;
    #[cfg(not(target_arch = "wasm32"))]
    let absolute = std::path::absolute(path)?;
    #[cfg(not(target_arch = "wasm32"))]
    let path = absolute.as_path();
    // Not database_key::open, which refuses a database without pages.
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    super::database_key::configure(&conn, key)?;
    let pages: i64 = conn.pragma_query_value(None, "page_count", |r| r.get(0))?;
    Ok(pages > 0 && !schema(&conn)?.is_empty())
}

/// Whether the file at `path` is an unencrypted SQLite database. Encrypted
/// databases do not start with SQLite's plaintext header.
#[cfg(not(target_arch = "wasm32"))]
pub fn is_plaintext_file(path: &std::path::Path) -> Result<bool> {
    use std::io::Read;
    let mut header = [0u8; 16];
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    Ok(file.read_exact(&mut header).is_ok() && &header == b"SQLite format 3\0")
}

/// Encrypt the plaintext database at `path` with `key`, keeping its path.
///
/// The copy goes into `<path>.encrypting` and then replaces the original with
/// a rename. The plaintext database is untouched until that rename, so an
/// interruption leaves only a partial copy, which the next attempt discards.
/// Write the database's key record before calling this, so the
/// encrypted database is never left without one.
#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt_in_place(
    path: &std::path::Path,
    key: &super::database_key::DatabaseKey,
) -> Result<()> {
    let path = std::path::absolute(path)?;
    ensure!(
        is_plaintext_file(&path)?,
        "{} is not a plaintext database",
        path.display()
    );
    let mut staging = path.as_os_str().to_owned();
    staging.push(".encrypting");
    let staging = std::path::PathBuf::from(staging);
    let mut staging_journal = staging.as_os_str().to_owned();
    staging_journal.push("-journal");
    for leftover in [staging.as_path(), std::path::Path::new(&staging_journal)] {
        match std::fs::remove_file(leftover) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            result => result?,
        }
    }
    copy_into_encrypted(&path, None, &staging, key)?;
    // Native storage keeps the complete database layout. Browser copies use
    // the private vault's separate, fixed legacy conversion instead.
    let migrated = super::Storage::connect_encrypted(
        &staging,
        key,
        super::database_key::OpenPurpose::OpenExisting,
    )?;
    check_integrity(&migrated.conn)?;
    drop(migrated);
    std::fs::File::open(&staging)?.sync_all()?;
    std::fs::rename(&staging, &path)?;
    if let Some(directory) = path.parent() {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

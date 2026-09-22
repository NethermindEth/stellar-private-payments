//! Only encrypted snapshots enter this pool. Existing databases are never
//! replaced.
use anyhow::{Result, ensure};
use sqlite_wasm_vfs::sahpool::{OpfsSAHPoolCfg, OpfsSAHPoolUtil, install};
use std::path::Path;
use stellar_private_payments::state::database_key::{self, DatabaseKey};

pub(super) const DATABASE: &str = "spp.encrypted.db";
const STAGE: &str = "spp.restore-stage.db";
const PENDING: &str = "spp.restore-pending-";
const COMPLETE: &str = "spp.restore-complete-";

fn marker_names(pool: &OpfsSAHPoolUtil) -> Vec<String> {
    pool.list()
        .into_iter()
        .filter(|n| {
            let name = n.trim_start_matches('/');
            name.starts_with(PENDING) || name.starts_with(COMPLETE)
        })
        .collect()
}

/// A pending restore cannot become an ordinary database merely because page 1
/// survived.
pub(super) fn check_open(pool: &OpfsSAHPoolUtil) -> Result<()> {
    let names = marker_names(pool);
    ensure!(
        names.iter().all(|n| {
            n.trim_start_matches('/')
                .strip_prefix(PENDING)
                .is_none_or(|tag| {
                    names
                        .iter()
                        .any(|other| other.trim_start_matches('/') == format!("{COMPLETE}{tag}"))
                })
        }),
        "database restore is incomplete; retry with the same complete backup"
    );
    Ok(())
}

pub(super) fn finish_open(pool: &OpfsSAHPoolUtil) -> Result<()> {
    let mut names = marker_names(pool);
    names.sort_by_key(|n| n.trim_start_matches('/').starts_with(COMPLETE));
    for name in names {
        pool.delete_db(&name)?;
    }
    Ok(())
}

pub(super) fn validate_export(
    pool: &OpfsSAHPoolUtil,
    key: &DatabaseKey,
    snapshot: &[u8],
) -> Result<()> {
    // SAH pools intentionally prohibit a second handle for the same file.
    // Validate an encrypted scratch copy without closing the application's
    // connection.
    if pool.exists(STAGE)? {
        pool.delete_db(STAGE)?;
    }
    pool.import_db_unchecked(STAGE, snapshot)?;
    let result = database_key::validate_backup(Path::new(STAGE), key);
    pool.delete_db(STAGE)?;
    result
}

pub(super) async fn restore(key: &DatabaseKey, snapshot: &[u8]) -> Result<()> {
    ensure!(
        snapshot.len() >= 512 && !snapshot.starts_with(b"SQLite format 3\0"),
        "expected encrypted database snapshot"
    );
    let cfg = OpfsSAHPoolCfg {
        directory: ".opfs-sahpool-encrypted".into(),
        ..Default::default()
    };
    let pool = install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true).await?;
    let result = restore_owned(&pool, key, snapshot);
    #[allow(unsafe_code)]
    unsafe {
        sqlite_wasm_rs::sqlite3mc_vfs_destroy(c"multipleciphers-opfs-sahpool".as_ptr());
    }
    let closed = pool.pause_vfs();
    result?;
    closed?;
    Ok(())
}

#[allow(unsafe_code)]
fn restore_owned(pool: &OpfsSAHPoolUtil, key: &DatabaseKey, snapshot: &[u8]) -> Result<()> {
    // SAFETY: pool registered this VFS and all local connections close before
    // destruction.
    ensure!(
        unsafe { sqlite_wasm_rs::sqlite3mc_vfs_create(c"opfs-sahpool".as_ptr(), 1) }
            == sqlite_wasm_rs::SQLITE_OK,
        "cannot register restore codec"
    );
    let tag = database_key::backup_restore_tag(key, snapshot);
    let pending = format!("{PENDING}{tag}");
    let complete = format!("{COMPLETE}{tag}");
    let names = marker_names(pool);
    ensure!(
        names
            .iter()
            .all(|n| [pending.as_str(), complete.as_str()].contains(&n.trim_start_matches('/'))),
        "another restore is pending; use its original backup"
    );
    let owns_pending = pool.exists(&pending)?;
    let owns_complete = pool.exists(&complete)?;
    if pool.exists(DATABASE)? {
        ensure!(
            owns_pending || owns_complete,
            "encrypted database already exists; restore will not overwrite it"
        );
        if owns_complete {
            ensure!(
                pool.export_db(DATABASE)? == snapshot,
                "restored database has changed; replacement refused"
            );
            database_key::validate_backup(Path::new(DATABASE), key)?;
            return Ok(());
        }
    }
    if pool.exists(STAGE)? {
        pool.delete_db(STAGE)?;
    }
    pool.import_db_unchecked(STAGE, snapshot)?;
    let validation = database_key::validate_backup(Path::new(STAGE), key);
    pool.delete_db(STAGE)?;
    validation?;
    // The authenticated filename and its mapping are flushed before any
    // canonical write.
    if !owns_pending {
        pool.import_db_unchecked(&pending, b"restore-v1")?;
    }
    if pool.exists(DATABASE)? {
        pool.delete_db(DATABASE)?;
    }
    pool.import_db_unchecked(DATABASE, snapshot)?;
    database_key::validate_backup(Path::new(DATABASE), key)?;
    if !owns_complete {
        pool.import_db_unchecked(&complete, b"complete-v1")?;
    }
    Ok(())
}

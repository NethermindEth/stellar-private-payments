//! Public chain cache and a private vault unlocked exclusively by a wallet.
use crate::protocol::StorageStatus;
use anyhow::{Result, anyhow, ensure};
use std::path::Path;
use stellar_private_payments::state::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
    encrypted_migration::{copy_into_encrypted, has_tables},
    wallet_vault::{self, WalletContext},
};

const ENCRYPTED_DB: &str = "spp.encrypted.db";
const PUBLIC_DB: &str = "spp.public.db";

pub(super) async fn open_public() -> Result<SqliteStorage> {
    pools::ensure_encrypted().await?;
    SqliteStorage::connect_public(PUBLIC_DB)
}
const KEY_DB: &str = "spp.key.db";
/// The unencrypted database of earlier versions.
const PLAINTEXT_DB: &str = "spp.db";

/// Report what the database needs before it can be used.
pub(super) async fn status(unlocked: bool) -> Result<StorageStatus> {
    if unlocked {
        return Ok(StorageStatus::Unlocked);
    }
    pools::ensure_encrypted().await?;
    if wallet_vault::context(Path::new(KEY_DB))?.is_some() {
        return Ok(StorageStatus::Locked);
    }
    if pools::encrypted_exists(ENCRYPTED_DB)? {
        return Ok(StorageStatus::RecoveryRequired);
    }
    Ok(if pools::plaintext_exists(PLAINTEXT_DB).await? {
        StorageStatus::Unencrypted
    } else {
        StorageStatus::New
    })
}

/// Save the envelope first so interrupted creation or migration is resumable.
pub(super) async fn create_wallet(context: WalletContext, secret: &str) -> Result<SqliteStorage> {
    ensure!(
        matches!(
            status(false).await?,
            StorageStatus::New | StorageStatus::Unencrypted
        ),
        "existing local data must be unlocked or explicitly reset"
    );
    let key = DatabaseKey::generate()?;
    wallet_vault::create(Path::new(KEY_DB), &key, context, secret)?;
    open_key(&key).await
}

pub(super) async fn wallet_context() -> Result<Option<WalletContext>> {
    pools::ensure_encrypted().await?;
    wallet_vault::context(Path::new(KEY_DB))
}

pub(super) async fn unlock_wallet(context: &WalletContext, secret: &str) -> Result<SqliteStorage> {
    pools::ensure_encrypted().await?;
    let key = wallet_vault::unlock(Path::new(KEY_DB), context, secret)?;
    open_key(&key).await
}

async fn open_key(key: &DatabaseKey) -> Result<SqliteStorage> {
    let plaintext = pools::plaintext_exists(PLAINTEXT_DB).await?;
    let complete =
        pools::encrypted_exists(ENCRYPTED_DB)? && has_tables(Path::new(ENCRYPTED_DB), key)?;
    if !complete {
        // Creating the wallet vault was interrupted: finish it.
        pools::delete_encrypted(ENCRYPTED_DB)?;
        if !plaintext {
            return SqliteStorage::connect_encrypted(ENCRYPTED_DB, key, OpenPurpose::CreateNew);
        }
        copy_plaintext(key).await?;
    } else if plaintext {
        // The copy committed, but deleting the unencrypted database did not.
        pools::remove_plaintext(PLAINTEXT_DB).await?;
    }
    SqliteStorage::connect_encrypted(ENCRYPTED_DB, key, OpenPurpose::OpenExisting)
}

/// Explicitly delete all local data. The caller closes connections first.
pub(super) async fn reset() -> Result<()> {
    pools::ensure_encrypted().await?;
    pools::delete_encrypted(ENCRYPTED_DB)?;
    pools::delete_encrypted(KEY_DB)?;
    pools::delete_encrypted(PUBLIC_DB)?;
    if pools::plaintext_exists(PLAINTEXT_DB).await? {
        pools::remove_plaintext(PLAINTEXT_DB).await?;
    }
    Ok(())
}

/// Release the OPFS pools so another worker can take them.
pub(super) fn release() {
    pools::release();
}

/// Copy `spp.db` into a new encrypted database, then delete `spp.db`.
async fn copy_plaintext(key: &DatabaseKey) -> Result<()> {
    copy_into_encrypted(
        Path::new(PLAINTEXT_DB),
        Some(pools::PLAINTEXT_VFS),
        Path::new(ENCRYPTED_DB),
        key,
    ).map_err(|error| anyhow!("Legacy database migration failed; the original plaintext data is preserved. Retry unlocking to resume migration. If it keeps failing, stop and seek help recovering the existing browser profile. This app has no local-data export; reset deletes the original too. Details: {error:#}"))?;
    pools::remove_plaintext(PLAINTEXT_DB).await
}

/// The OPFS pools behind the SQLite files.
///
/// The encrypted pool, wrapped by SQLite3MC, is the default VFS. The pool of
/// earlier, unencrypted versions is installed under its own name only when
/// its directory exists, and removed with its directory once `spp.db` is gone.
#[cfg(target_arch = "wasm32")]
mod pools {
    use std::cell::RefCell;

    use anyhow::{Result, anyhow};
    use gloo_timers::future::TimeoutFuture;
    use sqlite_wasm_vfs::sahpool::{OpfsSAHError, OpfsSAHPoolCfg, OpfsSAHPoolUtil, install};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{FileSystemDirectoryHandle, FileSystemRemoveOptions, WorkerGlobalScope};

    pub(super) const PLAINTEXT_VFS: &str = "opfs-sahpool-plaintext";
    const PLAINTEXT_DIRECTORY: &str = ".opfs-sahpool";
    const ENCRYPTED_VFS: &str = "opfs-sahpool";
    const ENCRYPTED_DIRECTORY: &str = ".opfs-sahpool-encrypted";

    // A prior page's worker still releases its OPFS sync access handles
    // asynchronously after termination, so a fresh worker started right
    // after a navigation can transiently race that teardown. Retry for a
    // bit before treating the lock as held by a separate tab or window.
    const LOCK_RETRY_ATTEMPTS: u32 = 10;
    const LOCK_RETRY_DELAY_MS: u32 = 200;
    const LOCKED_BY_ANOTHER_TAB: &str = "Another tab or window is using this app's local \
        database. Please close other tabs/windows running this app, then reload this page.";

    thread_local! {
        static ENCRYPTED: RefCell<Option<OpfsSAHPoolUtil>> = const { RefCell::new(None) };
        static PLAINTEXT: RefCell<Option<OpfsSAHPoolUtil>> = const { RefCell::new(None) };
    }

    pub(super) async fn ensure_encrypted() -> Result<()> {
        // Validate the linked library before installing or opening any VFS.
        #[allow(unsafe_code)]
        // SAFETY: SQLite3MC returns a static NUL-terminated version string.
        let actual = unsafe { std::ffi::CStr::from_ptr(sqlite_wasm_rs::sqlite3mc_version()) };
        mod cipher_version {
            include!("../../../native/sqlite3mc_version.rs");
        }
        let expected = cipher_version::VERSION;
        anyhow::ensure!(
            actual.to_bytes() == format!("SQLite3 Multiple Ciphers {expected}").as_bytes(),
            "Unsupported SQLite3MC backend; rebuild with sdk/web/scripts/build.sh"
        );
        if ENCRYPTED.with(|p| p.borrow().is_some()) {
            return Ok(());
        }
        let util = install_pool(ENCRYPTED_VFS, ENCRYPTED_DIRECTORY, true).await?;
        // SAH installation replaces the default VFS. Attach SQLite3MC's codec
        // wrapper once it exists.
        #[allow(unsafe_code)]
        // SAFETY: the named VFS has just been registered in this worker.
        // SQLite owns the wrapper until release() destroys it.
        let rc = unsafe { sqlite_wasm_rs::sqlite3mc_vfs_create(c"opfs-sahpool".as_ptr(), 1) };
        if rc != sqlite_wasm_rs::SQLITE_OK {
            util.pause_vfs()?;
            return Err(anyhow!("Failed to register encrypted OPFS storage"));
        }
        ENCRYPTED.with(|p| *p.borrow_mut() = Some(util));
        Ok(())
    }

    pub(super) fn encrypted_exists(name: &str) -> Result<bool> {
        with_encrypted(|pool| Ok(pool.exists(name)?))
    }

    /// Delete `name` and its journal from the encrypted pool, if present.
    pub(super) fn delete_encrypted(name: &str) -> Result<()> {
        with_encrypted(|pool| {
            pool.delete_db(name)?;
            pool.delete_db(&format!("{name}-journal"))?;
            Ok(())
        })
    }

    pub(super) async fn plaintext_exists(name: &str) -> Result<bool> {
        if !ensure_plaintext().await? {
            return Ok(false);
        }
        PLAINTEXT.with(|p| match p.borrow().as_ref() {
            Some(pool) => Ok(pool.exists(name)?),
            None => Ok(false),
        })
    }

    /// Delete `name` from the unencrypted pool, then the pool's directory.
    pub(super) async fn remove_plaintext(name: &str) -> Result<()> {
        if let Some(pool) = PLAINTEXT.with(|p| p.borrow_mut().take()) {
            pool.delete_db(name)?;
            pool.delete_db(&format!("{name}-journal"))?;
            pool.pause_vfs()?;
        }
        let options = FileSystemRemoveOptions::new();
        options.set_recursive(true);
        JsFuture::from(
            opfs_root()
                .await?
                .remove_entry_with_options(PLAINTEXT_DIRECTORY, &options),
        )
        .await
        .map_err(js_error)?;
        Ok(())
    }

    pub(super) fn release() {
        // SAFETY: the worker's connections have been dropped by the caller.
        #[allow(unsafe_code)]
        unsafe {
            sqlite_wasm_rs::sqlite3mc_vfs_destroy(c"multipleciphers-opfs-sahpool".as_ptr());
        }
        for pool in [&ENCRYPTED, &PLAINTEXT] {
            pool.with(|p| {
                if let Some(pool) = p.borrow().as_ref()
                    && let Err(e) = pool.pause_vfs()
                {
                    tracing::debug!("[WORKER-STORAGE] pause_vfs failed: {e:#}");
                }
            });
        }
    }

    fn with_encrypted<T>(f: impl FnOnce(&OpfsSAHPoolUtil) -> Result<T>) -> Result<T> {
        ENCRYPTED.with(|p| {
            f(p.borrow()
                .as_ref()
                .ok_or_else(|| anyhow!("OPFS unavailable"))?)
        })
    }

    /// Install the unencrypted pool if its directory exists; whether it is
    /// installed afterwards.
    async fn ensure_plaintext() -> Result<bool> {
        if PLAINTEXT.with(|p| p.borrow().is_some()) {
            return Ok(true);
        }
        if !directory_exists(PLAINTEXT_DIRECTORY).await? {
            return Ok(false);
        }
        let util = install_pool(PLAINTEXT_VFS, PLAINTEXT_DIRECTORY, false).await?;
        PLAINTEXT.with(|p| *p.borrow_mut() = Some(util));
        Ok(true)
    }

    async fn install_pool(
        vfs_name: &str,
        directory: &str,
        default_vfs: bool,
    ) -> Result<OpfsSAHPoolUtil> {
        let cfg = OpfsSAHPoolCfg {
            vfs_name: vfs_name.into(),
            directory: directory.into(),
            ..OpfsSAHPoolCfg::default()
        };
        let mut attempt = 0;
        loop {
            match install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, default_vfs).await {
                Ok(util) => return Ok(util),
                Err(e) if is_locked(&e) && attempt < LOCK_RETRY_ATTEMPTS => {
                    attempt = attempt.saturating_add(1);
                    tracing::debug!(
                        attempt,
                        "[WORKER-STORAGE] OPFS SAH pool still locked by a previous worker, retrying"
                    );
                    TimeoutFuture::new(LOCK_RETRY_DELAY_MS).await;
                }
                Err(e) => {
                    tracing::error!(details = ?e, "[WORKER-STORAGE] fatal error installing OPFS Sqlite VFS");
                    return Err(anyhow!(if is_locked(&e) {
                        LOCKED_BY_ANOTHER_TAB
                    } else {
                        "Failed to initialize local database storage."
                    }));
                }
            }
        }
    }

    fn is_locked(err: &OpfsSAHError) -> bool {
        // The error's Display and Debug do not include the wrapped JsValue, so
        // inspect the DOMException the browser throws when another tab or
        // worker still holds the OPFS sync access handles.
        let OpfsSAHError::CreateSyncAccessHandle(js_err) = err else {
            return false;
        };
        js_err
            .dyn_ref::<web_sys::DomException>()
            .is_some_and(|e| e.name() == "NoModificationAllowedError")
    }

    async fn opfs_root() -> Result<FileSystemDirectoryHandle> {
        let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
        Ok(JsFuture::from(scope.navigator().storage().get_directory())
            .await
            .map_err(js_error)?
            .unchecked_into())
    }

    async fn directory_exists(name: &str) -> Result<bool> {
        match JsFuture::from(opfs_root().await?.get_directory_handle(name)).await {
            Ok(_) => Ok(true),
            Err(e)
                if e.dyn_ref::<web_sys::DomException>()
                    .is_some_and(|e| e.name() == "NotFoundError") =>
            {
                Ok(false)
            }
            Err(e) => Err(js_error(e)),
        }
    }

    fn js_error(value: JsValue) -> anyhow::Error {
        anyhow!(
            "OPFS error: {}",
            value
                .dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
                .unwrap_or_else(|| format!("{value:?}"))
        )
    }
}

/// Outside the browser the files are plain files in the working directory,
/// so the worker's logic builds and runs in native tests.
#[cfg(not(target_arch = "wasm32"))]
mod pools {
    use anyhow::Result;

    pub(super) const PLAINTEXT_VFS: &str = "unix";

    pub(super) async fn ensure_encrypted() -> Result<()> {
        Ok(())
    }

    pub(super) fn encrypted_exists(name: &str) -> Result<bool> {
        Ok(std::path::Path::new(name).exists())
    }

    pub(super) fn delete_encrypted(name: &str) -> Result<()> {
        for path in [name.to_string(), format!("{name}-journal")] {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                result => result?,
            }
        }
        Ok(())
    }

    pub(super) async fn plaintext_exists(name: &str) -> Result<bool> {
        Ok(std::path::Path::new(name).exists())
    }

    pub(super) async fn remove_plaintext(name: &str) -> Result<()> {
        delete_encrypted(name)
    }

    pub(super) fn release() {}
}

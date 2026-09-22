//! Opt-in encrypted storage. Keys are random 256-bit secrets supplied by the caller.
//! Opening/creating a database must be serialized by its owner; key wrapping and
//! wallet signing belong to the key provider, never to the SQLite layer.
use anyhow::{Result, bail, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    ffi::{c_char, c_int, c_void},
    path::Path,
};
use zeroize::Zeroizing;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "database_key_tests.rs"]
mod tests;

pub struct DatabaseKey(Zeroizing<[u8; 32]>);
impl DatabaseKey {
    /// Take ownership of a database key, zeroizing this owned copy on drop.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generate a fresh database key using the platform cryptographic RNG.
    /// Persist a recoverable wrapped copy before using it to create a database.
    pub fn generate() -> Result<Self> {
        let mut key = Self::new([0; 32]);
        getrandom::getrandom(&mut key[..])
            .map_err(|_| anyhow::anyhow!("database key generation failed"))?;
        Ok(key)
    }
}
impl std::fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatabaseKey([REDACTED])")
    }
}
impl std::ops::Deref for DatabaseKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DatabaseKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl AsRef<[u8]> for DatabaseKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPurpose {
    CreateNew,
    OpenExisting,
}

#[async_trait::async_trait(?Send)]
pub trait DatabaseKeyProvider {
    /// Return the same recoverable key for subsequent opens of this database.
    /// Use a dedicated domain for future wallet wrapping, never the SEP-53
    /// privacy-key signature or a raw wallet signature as this database key.
    async fn acquire(&self, database_id: &str, purpose: OpenPurpose) -> Result<DatabaseKey>;
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn sqlite3_key(db: *mut rusqlite::ffi::sqlite3, key: *const c_void, len: c_int) -> c_int;
    fn sqlite3mc_cipher_index(name: *const c_char) -> c_int;
    fn sqlite3mc_config(
        db: *mut rusqlite::ffi::sqlite3,
        name: *const c_char,
        value: c_int,
    ) -> c_int;
    fn sqlite3mc_config_cipher(
        db: *mut rusqlite::ffi::sqlite3,
        cipher: *const c_char,
        name: *const c_char,
        value: c_int,
    ) -> c_int;
}

// The caller owns the OPFS pool and checks logical filename absence for CreateNew.
// Native creation reserves a new path atomically, refusing existing files.
pub(crate) fn open(path: &Path, key: &DatabaseKey, purpose: OpenPurpose) -> Result<Connection> {
    // A native filesystem filename is never a SQLite URI. An absolute path
    // prevents a literal "file:" filename from selecting a different database.
    #[cfg(not(target_arch = "wasm32"))]
    let absolute = std::path::absolute(path)?;
    #[cfg(not(target_arch = "wasm32"))]
    let path = absolute.as_path();
    if matches!(purpose, OpenPurpose::OpenExisting) {
        validate_read_only(path, Some(key))?;
    }
    #[cfg(not(target_arch = "wasm32"))]
    if matches!(purpose, OpenPurpose::CreateNew) {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    #[cfg(target_arch = "wasm32")]
    let flags = if matches!(purpose, OpenPurpose::CreateNew) {
        flags | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        flags
    };
    let conn = Connection::open_with_flags(path, flags)?;
    configure(&conn, key)?;
    // This is the first schema access: a successful key API call alone proves nothing.
    let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    let pages: i64 = conn.pragma_query_value(None, "page_count", |r| r.get(0))?;
    if matches!(purpose, OpenPurpose::OpenExisting) && pages == 0 {
        bail!("existing database is empty");
    }
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    let journal: String = conn.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
    ensure!(journal == "delete", "unsupported journal mode");
    Ok(conn)
}

// The raw: prefix selects the MC raw-key API; no password-derived database key.
#[allow(unsafe_code)]
pub(crate) fn configure(conn: &Connection, key: &DatabaseKey) -> Result<()> {
    // SAFETY: conn owns the live SQLite handle throughout these synchronous
    // calls. C strings are NUL-terminated; sqlite3_key copies the 36-byte buffer
    // before it is zeroized, and no raw pointer escapes this function.
    unsafe {
        let db = conn.handle();
        let cipher = sqlite3mc_cipher_index(c"chacha20".as_ptr());
        ensure!(
            cipher > 0 && sqlite3mc_config(db, c"cipher".as_ptr(), cipher) == cipher,
            "cipher unavailable"
        );
        ensure!(
            sqlite3mc_config(db, c"hmac_check".as_ptr(), 1) == 1,
            "integrity configuration failed"
        );
        for (name, value) in [
            (c"legacy", 0),
            (c"plaintext_header_size", 0),
            (c"kdf_iter", 64007),
        ] {
            ensure!(
                sqlite3mc_config_cipher(db, c"chacha20".as_ptr(), name.as_ptr(), value) == value,
                "cipher configuration failed"
            );
        }
        let mut raw = Zeroizing::new([0u8; 36]);
        raw[..4].copy_from_slice(b"raw:");
        raw[4..].copy_from_slice(key.as_ref());
        ensure!(
            sqlite3_key(db, raw.as_ptr().cast(), 36) == rusqlite::ffi::SQLITE_OK,
            "key setup failed"
        );
    }
    Ok(())
}

pub fn clear_transport(bytes: &mut [u8]) {
    use zeroize::Zeroize;
    bytes.zeroize();
}

// Authenticate the encrypted first page without allowing hot-journal recovery.
// The immutable handle is closed before the normal recovery-capable handle opens.
// This is a short preflight under the application's single-owner database policy;
// it must never be used as a long-lived snapshot while another writer is active.
pub(crate) fn validation_connection(path: &Path) -> Result<Connection> {
    #[cfg(not(target_arch = "wasm32"))]
    let absolute = std::path::absolute(path)?;
    #[cfg(not(target_arch = "wasm32"))]
    let path = absolute.as_path();
    let path = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("database path must be UTF-8"))?;
    let encoded: String = path
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/._-~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    Connection::open_with_flags(
        format!("file:{encoded}?mode=ro&immutable=1"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Into::into)
}
pub(crate) fn validate_read_only(path: &Path, key: Option<&DatabaseKey>) -> Result<()> {
    let conn = validation_connection(path)?;
    if let Some(key) = key {
        configure(&conn, key)?;
    }
    // schema_version reads the authenticated page-1 header without traversing
    // possibly inconsistent, uncommitted btree pages left by a crash.
    let _: i64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    ensure!(pages > 0, "existing database is empty");
    Ok(())
}

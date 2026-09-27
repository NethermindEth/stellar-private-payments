//! Password protection for the database key.
//!
//! The random key from [`DatabaseKey::generate`] is sealed with a key derived
//! from the user's password by Argon2id. The stored record holds the sealed
//! key and the derivation parameters, never the password or the database key.
//! Changing the password seals the same database key again, so the database
//! itself is not rewritten.

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::database_key::DatabaseKey;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "password_vault_tests.rs"]
mod tests;

const RECORD_VERSION: u32 = 1;
const ALGORITHM: &str = "argon2id";
// RFC 9106's option for memory-constrained environments, with one lane
// because browser workers derive single-threaded.
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
// Limits on parameters read back from a record, so a damaged record cannot
// make unlocking allocate or compute without bound.
const MAX_MEMORY_KIB: u32 = MEMORY_KIB;
const MAX_ITERATIONS: u32 = ITERATIONS;
const MAX_PARALLELISM: u32 = PARALLELISM;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEALED_KEY_LEN: usize = 32 + 16;

/// Minimum length of a new password, in characters.
pub const MIN_PASSWORD_CHARS: usize = 15;
/// Maximum length of a password, in UTF-8 bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("wrong password")]
    WrongPassword,
    #[error("use a password of at least {MIN_PASSWORD_CHARS} characters")]
    PasswordTooShort,
    #[error("use a password of at most {MAX_PASSWORD_BYTES} bytes")]
    PasswordTooLong,
    #[error("the password record is damaged or unsupported")]
    InvalidRecord,
}

/// Check a new password against the length policy. Passwords are used exactly
/// as entered: never trimmed or normalized.
pub fn validate_new_password(password: &str) -> Result<(), VaultError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::PasswordTooLong);
    }
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::PasswordTooShort);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

impl Kdf {
    fn generate() -> Result<Self> {
        #[cfg(test)]
        let (memory_kib, iterations) = (64, 1);
        #[cfg(not(test))]
        let (memory_kib, iterations) = (MEMORY_KIB, ITERATIONS);
        Self::generate_with(memory_kib, iterations)
    }

    fn generate_with(memory_kib: u32, iterations: u32) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt)
            .map_err(|_| anyhow::anyhow!("password salt generation failed"))?;
        Ok(Self {
            algorithm: ALGORITHM.into(),
            memory_kib,
            iterations,
            parallelism: PARALLELISM,
            salt: STANDARD.encode(salt),
        })
    }

    fn derive(&self, password: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if self.algorithm != ALGORITHM
            || self.memory_kib > MAX_MEMORY_KIB
            || !(1..=MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(VaultError::InvalidRecord);
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(VaultError::PasswordTooLong);
        }
        let salt = decode(&self.salt, SALT_LEN)?;
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| VaultError::InvalidRecord)?;
        let mut derived = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &salt, &mut derived[..])
            .map_err(|_| VaultError::InvalidRecord)?;
        Ok(derived)
    }
}

/// A database key sealed with a password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PasswordRecord {
    version: u32,
    kdf: Kdf,
    nonce: String,
    sealed_key: String,
}

impl PasswordRecord {
    /// Seal `key` with a new `password`, checking the password policy first.
    /// Use this both for a new database and to change the password.
    pub fn seal(key: &DatabaseKey, password: &str) -> Result<Self> {
        validate_new_password(password)?;
        Self::seal_with(key, password, Kdf::generate()?)
    }

    fn seal_with(key: &DatabaseKey, password: &str, kdf: Kdf) -> Result<Self> {
        let wrapping_key = kdf.derive(password)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| anyhow::anyhow!("password nonce generation failed"))?;
        let sealed = XSalsa20Poly1305::new(wrapping_key.as_ref().into())
            .encrypt(&Nonce::from(nonce), key.as_ref())
            .map_err(|_| anyhow::anyhow!("sealing the database key failed"))?;
        Ok(Self {
            version: RECORD_VERSION,
            kdf,
            nonce: STANDARD.encode(nonce),
            sealed_key: STANDARD.encode(sealed),
        })
    }

    /// Recover the database key. A wrong password and a record that was
    /// altered after sealing both fail as [`VaultError::WrongPassword`].
    pub fn open(&self, password: &str) -> Result<DatabaseKey, VaultError> {
        if self.version != RECORD_VERSION {
            return Err(VaultError::InvalidRecord);
        }
        let nonce: [u8; NONCE_LEN] = decode(&self.nonce, NONCE_LEN)?
            .try_into()
            .map_err(|_| VaultError::InvalidRecord)?;
        let sealed = decode(&self.sealed_key, SEALED_KEY_LEN)?;
        let wrapping_key = self.kdf.derive(password)?;
        let opened = Zeroizing::new(
            XSalsa20Poly1305::new(wrapping_key.as_ref().into())
                .decrypt(&Nonce::from(nonce), sealed.as_slice())
                .map_err(|_| VaultError::WrongPassword)?,
        );
        let mut key = DatabaseKey::new([0; 32]);
        key.copy_from_slice(&opened);
        Ok(key)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(json: &str) -> Result<Self, VaultError> {
        serde_json::from_str(json).map_err(|_| VaultError::InvalidRecord)
    }
}

fn decode(value: &str, len: usize) -> Result<Vec<u8>, VaultError> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == len)
        .ok_or(VaultError::InvalidRecord)
}

/// Read the password record kept in the plain SQLite file at `path`, if the
/// file and its record exist. Browser storage keeps the record this way, so
/// replacing it is a SQLite transaction and cannot leave a half-written file.
pub fn read_record_database(path: &std::path::Path) -> Result<Option<PasswordRecord>> {
    let json = read_optional_record(path, "password_record")?;
    json.map(|json| Ok(PasswordRecord::from_json(&json)?))
        .transpose()
}

/// Open existing metadata without creating a file or table. Read/write mode
/// permits SQLite to recover a hot journal, but SQLITE_OPEN_CREATE is omitted.
pub(crate) fn read_optional_record(path: &std::path::Path, table: &str) -> Result<Option<String>> {
    use rusqlite::{Connection, Error, ErrorCode, OpenFlags, OptionalExtension};
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(Error::SqliteFailure(error, _)) if error.code == ErrorCode::CannotOpen => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    // Only internal constant table names reach this helper.
    Ok(conn
        .query_row(
            &format!("SELECT record FROM {table} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .optional()?)
}

/// Store `record` in the plain SQLite file at `path`, replacing any earlier
/// one in a single transaction.
pub fn write_record_database(path: &std::path::Path, record: &PasswordRecord) -> Result<()> {
    let conn = rusqlite::Connection::open(path)?;
    create_record_table(&conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO password_record (id, record) VALUES (1, ?1)",
        [record.to_json()?],
    )?;
    Ok(())
}

fn create_record_table(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS password_record (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             record TEXT NOT NULL
         )",
    )?;
    Ok(())
}

/// Read a password from a file, dropping one trailing newline (`\n` or
/// `\r\n`) so files written by `echo` or an editor work.
#[cfg(not(target_arch = "wasm32"))]
pub fn read_password_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let mut password = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read password file {}: {e}", path.display()))?,
    );
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    Ok(password)
}

/// Where the password record of a native database lives: next to it, with
/// `.key` appended to the file name.
#[cfg(not(target_arch = "wasm32"))]
pub fn record_path(database: &std::path::Path) -> std::path::PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".key");
    name.into()
}

/// Supplies the database key of a native database from its password record.
///
/// Creating a database first writes a new record and only then returns the
/// key, so a database never exists without a way to unlock it.
#[cfg(not(target_arch = "wasm32"))]
pub struct PasswordKeyProvider {
    database: std::path::PathBuf,
    password: Zeroizing<String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PasswordKeyProvider {
    pub fn new(database: impl Into<std::path::PathBuf>, password: Zeroizing<String>) -> Self {
        Self {
            database: database.into(),
            password,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait(?Send)]
impl super::database_key::DatabaseKeyProvider for PasswordKeyProvider {
    async fn acquire(
        &self,
        _database_id: &str,
        purpose: super::database_key::OpenPurpose,
    ) -> Result<DatabaseKey> {
        use super::database_key::OpenPurpose;
        let path = record_path(&self.database);
        match purpose {
            OpenPurpose::CreateNew => {
                // A record without its database is left over from a create
                // that failed; replacing it cannot lock anyone out.
                anyhow::ensure!(
                    !self.database.exists(),
                    "a database already exists at {}",
                    self.database.display()
                );
                let key = DatabaseKey::generate()?;
                write_record(&path, &PasswordRecord::seal(&key, &self.password)?)?;
                Ok(key)
            }
            OpenPurpose::OpenExisting => {
                let json = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("read password record {}: {e}", path.display()))?;
                Ok(PasswordRecord::from_json(&json)?.open(&self.password)?)
            }
        }
    }
}

/// Replace the record at `path` atomically: write a private temporary file,
/// flush it, then rename it over the old record and flush the directory.
#[cfg(not(target_arch = "wasm32"))]
pub fn write_record(path: &std::path::Path, record: &PasswordRecord) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut temporary = path.as_os_str().to_owned();
    let mut suffix = [0u8; 16];
    getrandom::getrandom(&mut suffix)?;
    temporary.push(format!(".{}.tmp", hex::encode(suffix)));
    let temporary = std::path::PathBuf::from(temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(record.to_json()?.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    if let Some(directory) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

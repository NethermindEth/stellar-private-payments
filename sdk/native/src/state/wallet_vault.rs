//! Wallet-derived secrets seal a random database key.
//! Only public signing context and an encrypted key envelope are persisted.

use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::database_key::DatabaseKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletContext {
    pub version: u32,
    pub address: String,
    pub origin: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletRecord {
    context: WalletContext,
    sealed: WalletEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletEnvelope {
    version: u32,
    nonce: String,
    ciphertext: String,
}

impl WalletEnvelope {
    fn seal(key: &DatabaseKey, secret: &str) -> Result<Self> {
        validate_secret(secret)?;
        let material = Zeroizing::new(hex::decode(secret)?);
        let cipher = XSalsa20Poly1305::new_from_slice(&material)
            .map_err(|_| anyhow!("invalid wallet secret"))?;
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), key.as_ref())
            .map_err(|_| anyhow!("cannot seal wallet key"))?;
        Ok(Self {
            version: 2,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    fn open(&self, secret: &str) -> Result<DatabaseKey> {
        ensure!(self.version == 2, "unsupported wallet envelope version");
        let nonce = STANDARD.decode(&self.nonce)?;
        let ciphertext = STANDARD.decode(&self.ciphertext)?;
        ensure!(
            nonce.len() == 24 && ciphertext.len() == 48,
            "invalid wallet envelope"
        );
        let material = Zeroizing::new(hex::decode(secret)?);
        let cipher = XSalsa20Poly1305::new_from_slice(&material)
            .map_err(|_| anyhow!("invalid wallet secret"))?;
        let bytes = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| anyhow!("wallet could not unlock this database"))?,
        );
        Ok(DatabaseKey::new(bytes.as_slice().try_into()?))
    }
}

fn validate_context(context: &WalletContext) -> Result<()> {
    ensure!(
        context.version == 1
            && context.address.len() == 56
            && !context.origin.is_empty()
            && context.origin.len() <= 2048
            && context.salt.len() == 64
            && context.salt.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid wallet context"
    );
    Ok(())
}

/// Persist the first wallet envelope before creating the database. Never
/// replace an existing record: a retry must unlock and reuse its key.
pub fn create(path: &Path, key: &DatabaseKey, context: WalletContext, secret: &str) -> Result<()> {
    validate_context(&context)?;
    let record = WalletRecord {
        context,
        sealed: WalletEnvelope::seal(key, secret)?,
    };
    connection(path)?.execute(
        "INSERT INTO wallet_record (id, record) VALUES (1, ?1)",
        [serde_json::to_string(&record)?],
    )?;
    Ok(())
}

fn connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS wallet_record (
        id INTEGER PRIMARY KEY CHECK (id = 1), record TEXT NOT NULL
    )",
    )?;
    Ok(conn)
}

fn read(path: &Path) -> Result<Option<WalletRecord>> {
    let json = read_optional_record(path)?;
    json.map(|json| Ok(serde_json::from_str(&json)?))
        .transpose()
}

/// Open existing metadata without creating a file or table. Read/write mode
/// permits SQLite to recover a hot journal, but SQLITE_OPEN_CREATE is omitted.
fn read_optional_record(path: &Path) -> Result<Option<String>> {
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
        ["wallet_record"],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    Ok(conn
        .query_row("SELECT record FROM wallet_record WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?)
}

pub fn context(path: &Path) -> Result<Option<WalletContext>> {
    Ok(read(path)?.map(|record| record.context))
}

fn validate_secret(secret: &str) -> Result<()> {
    ensure!(
        secret.len() == 64 && secret.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid wallet-derived secret"
    );
    Ok(())
}

pub fn unlock(path: &Path, context: &WalletContext, secret: &str) -> Result<DatabaseKey> {
    validate_secret(secret)?;
    let record = read(path)?.ok_or_else(|| anyhow!("Freighter unlocking is not enabled"))?;
    ensure!(
        &record.context == context,
        "wallet enrollment changed; try again"
    );
    record.sealed.open(secret)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn wallet_creation_and_unlock_preserve_key() -> Result<()> {
        struct TestDir(std::path::PathBuf);
        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut suffix = [0u8; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir =
            TestDir(std::env::temp_dir().join(format!("spp-wallet-only-{}", hex::encode(suffix))));
        std::fs::create_dir(&dir.0)?;
        let path = dir.0.join("wallet.db");
        let key = DatabaseKey::generate()?;
        let ctx = WalletContext {
            version: 1,
            address: format!("G{}", "A".repeat(55)),
            origin: "https://example.test".into(),
            salt: "01".repeat(32),
        };
        let secret = "ab".repeat(32);
        assert!(create(&path, &key, ctx.clone(), "bad").is_err());
        assert!(context(&path)?.is_none());
        let mut malformed = ctx.clone();
        malformed.salt = "z".repeat(64);
        assert!(create(&path, &key, malformed, &secret).is_err());
        create(&path, &key, ctx.clone(), &secret)?;
        let mut altered = ctx.clone();
        altered.origin = "https://other.test".into();
        assert!(unlock(&path, &altered, &secret).is_err());
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        let bytes = std::fs::read(&path)?;
        assert!(create(&path, &DatabaseKey::generate()?, ctx.clone(), &secret).is_err());
        assert!(unlock(&path, &ctx, &"cd".repeat(32)).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        assert_eq!(
            std::fs::read(&path)?,
            bytes,
            "unlock must not rewrite the envelope"
        );
        Ok(())
    }
    #[test]
    fn reading_absent_metadata_does_not_create_files_or_tables() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("spp-wallet-metadata-{}.db", std::process::id()));
        assert!(context(&path)?.is_none());
        assert!(!path.exists());
        let conn = rusqlite::Connection::open(&path)?;
        conn.execute_batch("CREATE TABLE unrelated (value TEXT)")?;
        drop(conn);
        let before = std::fs::read(&path)?;
        assert!(context(&path)?.is_none());
        assert_eq!(std::fs::read(&path)?, before);
        std::fs::remove_file(path)?;
        Ok(())
    }
}

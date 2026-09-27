//! An optional wallet-derived secret seals the same key as the password.
//! Only public signing context and an encrypted key envelope are persisted.

use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::{
    database_key::DatabaseKey,
    password_vault::{PasswordRecord, read_optional_record, read_record_database},
};

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
    sealed: PasswordRecord,
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
    let json = read_optional_record(path, "wallet_record")?;
    json.map(|json| Ok(serde_json::from_str(&json)?))
        .transpose()
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

/// Authenticate with the password before adding a second envelope. A failed
/// enrollment never replaces the password or an existing wallet record.
pub fn enroll(path: &Path, password: &str, context: WalletContext, secret: &str) -> Result<()> {
    validate_secret(secret)?;
    ensure!(
        context.version == 1
            && context.address.len() == 56
            && context.origin.len() <= 2048
            && context.salt.len() == 64,
        "invalid wallet context"
    );
    let key = read_record_database(path)?
        .ok_or_else(|| anyhow!("set a password first"))?
        .open(password)?;
    let record = WalletRecord {
        context,
        sealed: PasswordRecord::seal(&key, secret)?,
    };
    connection(path)?.execute(
        "INSERT INTO wallet_record (id, record) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET record = excluded.record",
        [serde_json::to_string(&record)?],
    )?;
    Ok(())
}

pub fn unlock(path: &Path, context: &WalletContext, secret: &str) -> Result<DatabaseKey> {
    validate_secret(secret)?;
    let record = read(path)?.ok_or_else(|| anyhow!("Freighter unlocking is not enabled"))?;
    ensure!(
        &record.context == context,
        "wallet enrollment changed; try again"
    );
    Ok(record.sealed.open(secret)?)
}

/// Authenticate before revoking this method on the current database copy.
pub fn remove(path: &Path, password: &str) -> Result<()> {
    let _key = read_record_database(path)?
        .ok_or_else(|| anyhow!("password record is missing"))?
        .open(password)?;
    clear(path)
}

pub fn clear(path: &Path) -> Result<()> {
    connection(path)?.execute("DELETE FROM wallet_record", [])?;
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::state::password_vault::write_record_database;

    #[test]
    fn wallet_and_password_share_key_and_failures_preserve_recovery() -> Result<()> {
        struct TestDir(std::path::PathBuf);
        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut suffix = [0u8; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = TestDir(std::env::temp_dir().join(format!("spp-wallet-{}", hex::encode(suffix))));
        std::fs::create_dir(&dir.0)?;
        let path = dir.0.join("key.db");
        let password = "correct horse battery staple";
        let secret = "ab".repeat(32);
        let key = DatabaseKey::generate()?;
        let password_record = PasswordRecord::seal(&key, password)?;
        write_record_database(&path, &password_record)?;
        let ctx = WalletContext {
            version: 1,
            address: format!("G{}", "A".repeat(55)),
            origin: "https://example.test".into(),
            salt: "01".repeat(32),
        };
        assert!(context(&path)?.is_none());
        assert!(enroll(&path, "wrong password", ctx.clone(), &secret).is_err());
        assert!(context(&path)?.is_none());
        enroll(&path, password, ctx.clone(), &secret)?;
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        assert_eq!(read_record_database(&path)?, Some(password_record));
        assert!(unlock(&path, &ctx, &"cd".repeat(32)).is_err());
        let mut altered = ctx.clone();
        altered.salt = "02".repeat(32);
        assert!(unlock(&path, &altered, &secret).is_err());
        assert!(enroll(&path, "wrong password", altered.clone(), &secret).is_err());
        assert_eq!(context(&path)?, Some(ctx.clone()));
        write_record_database(
            &path,
            &PasswordRecord::seal(&key, "replacement password phrase")?,
        )?;
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        assert!(
            read_record_database(&path)?
                .expect("password record exists after changing the password")
                .open(password)
                .is_err()
        );
        let bytes = std::fs::read(&path)?;
        for sensitive in [
            password.to_string(),
            secret.clone(),
            hex::encode(key.as_ref()),
        ] {
            assert!(
                !bytes
                    .windows(sensitive.len())
                    .any(|w| w == sensitive.as_bytes())
            );
        }
        assert!(remove(&path, "wrong password").is_err());
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        let replacement_secret = "98".repeat(32);
        enroll(
            &path,
            "replacement password phrase",
            altered.clone(),
            &replacement_secret,
        )?;
        assert!(unlock(&path, &ctx, &secret).is_err());
        assert!(unlock(&path, &altered, &secret).is_err());
        assert_eq!(*unlock(&path, &altered, &replacement_secret)?, *key);
        remove(&path, "replacement password phrase")?;
        assert!(context(&path)?.is_none());
        assert!(unlock(&path, &ctx, &secret).is_err());
        assert_eq!(
            *read_record_database(&path)?
                .expect("clearing wallet access preserves the password record")
                .open("replacement password phrase")?,
            *key
        );
        Ok(())
    }
}

//! An optional passkey-derived secret seals the same key as the password.
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PasskeyContext {
    pub version: u32,
    pub credential_id: String,
    pub rp_id: String,
    pub origin: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRecord {
    context: PasskeyContext,
    sealed: PasswordRecord,
}

fn connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS passkey_record (
        id INTEGER PRIMARY KEY CHECK (id = 1), record TEXT NOT NULL
    )",
    )?;
    Ok(conn)
}

fn read(path: &Path) -> Result<Option<PasskeyRecord>> {
    let json = read_optional_record(path, "passkey_record")?;
    json.map(|json| Ok(serde_json::from_str(&json)?))
        .transpose()
}

pub fn context(path: &Path) -> Result<Option<PasskeyContext>> {
    Ok(read(path)?.map(|record| record.context))
}

fn validate_secret(secret: &str) -> Result<()> {
    ensure!(
        secret.len() == 64 && secret.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid passkey-derived secret"
    );
    Ok(())
}

/// Authenticate with the password before adding a second envelope. A failed
/// enrollment never replaces the password or an existing passkey record.
pub fn enroll(path: &Path, password: &str, context: PasskeyContext, secret: &str) -> Result<()> {
    validate_secret(secret)?;
    ensure!(
        context.version == 1
            && !context.origin.is_empty()
            && context.origin.len() <= 2048
            && !context.rp_id.is_empty()
            && context.rp_id.len() <= 253
            && context.credential_id.len() <= 1366
            && context.salt.len() == 64
            && context.salt.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid passkey context"
    );
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let credential = URL_SAFE_NO_PAD.decode(&context.credential_id)?;
    ensure!(
        !credential.is_empty() && credential.len() <= 1024,
        "invalid passkey credential ID"
    );
    let key = read_record_database(path)?
        .ok_or_else(|| anyhow!("set a password first"))?
        .open(password)?;
    let record = PasskeyRecord {
        context,
        sealed: PasswordRecord::seal(&key, secret)?,
    };
    connection(path)?.execute(
        "INSERT INTO passkey_record (id, record) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET record = excluded.record",
        [serde_json::to_string(&record)?],
    )?;
    Ok(())
}

pub fn unlock(path: &Path, context: &PasskeyContext, secret: &str) -> Result<DatabaseKey> {
    validate_secret(secret)?;
    let record = read(path)?.ok_or_else(|| anyhow!("Passkey unlocking is not enabled"))?;
    ensure!(
        &record.context == context,
        "passkey enrollment changed; try again"
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
    connection(path)?.execute("DELETE FROM passkey_record", [])?;
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::state::password_vault::write_record_database;

    #[test]
    fn passkey_and_password_share_key_and_failures_preserve_recovery() -> Result<()> {
        struct TestDir(std::path::PathBuf);
        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut suffix = [0u8; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir =
            TestDir(std::env::temp_dir().join(format!("spp-passkey-{}", hex::encode(suffix))));
        std::fs::create_dir(&dir.0)?;
        let path = dir.0.join("key.db");
        let password = "correct horse battery staple";
        let secret = "ab".repeat(32);
        let key = DatabaseKey::generate()?;
        let password_record = PasswordRecord::seal(&key, password)?;
        write_record_database(&path, &password_record)?;
        let ctx = PasskeyContext {
            version: 1,
            credential_id: "AQIDBA".into(),
            rp_id: "example.test".into(),
            origin: "https://example.test".into(),
            salt: "01".repeat(32),
        };
        assert!(context(&path)?.is_none());
        assert!(enroll(&path, "wrong password", ctx.clone(), &secret).is_err());
        assert!(context(&path)?.is_none());
        let wallet = super::super::wallet_vault::WalletContext {
            version: 1,
            address: format!("G{}", "A".repeat(55)),
            origin: ctx.origin.clone(),
            salt: "03".repeat(32),
        };
        super::super::wallet_vault::enroll(&path, password, wallet.clone(), &"ef".repeat(32))?;
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
        assert_eq!(
            *super::super::wallet_vault::unlock(&path, &wallet, &"ef".repeat(32))?,
            *key
        );
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
        assert_eq!(
            *super::super::wallet_vault::unlock(&path, &wallet, &"ef".repeat(32))?,
            *key
        );
        assert!(context(&path)?.is_none());
        assert!(unlock(&path, &ctx, &secret).is_err());
        assert_eq!(
            *read_record_database(&path)?
                .expect("clearing passkey access preserves the password record")
                .open("replacement password phrase")?,
            *key
        );
        Ok(())
    }
}

//! Wallet-derived secrets seal a random database key.
//! Only public signing context and an encrypted key envelope are persisted.

use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    database_key::DatabaseKey,
    password_vault::{PasswordRecord, read_optional_record},
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
    sealed: Envelope,
}

// The untagged legacy variant is read only during migration.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Envelope {
    Wallet(WalletEnvelope),
    Legacy(PasswordRecord),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletEnvelope {
    version: u32,
    nonce: String,
    ciphertext: String,
}

impl Envelope {
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
        Ok(Self::Wallet(WalletEnvelope {
            version: 2,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        }))
    }

    fn open(&self, secret: &str) -> Result<DatabaseKey> {
        match self {
            Self::Legacy(record) => Ok(record.open(secret)?),
            Self::Wallet(record) => {
                ensure!(record.version == 2, "unsupported wallet envelope version");
                let nonce = STANDARD.decode(&record.nonce)?;
                let ciphertext = STANDARD.decode(&record.ciphertext)?;
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
        sealed: Envelope::seal(key, secret)?,
    };
    connection(path)?.execute(
        "INSERT INTO wallet_record (id, record) VALUES (1, ?1)",
        [serde_json::to_string(&record)?],
    )?;
    Ok(())
}

/// Called only after the actual database was opened successfully. Replace the
/// legacy envelope and retire old browser unlock methods in one transaction.
pub fn finish_wallet_migration(
    path: &Path,
    key: &DatabaseKey,
    context: &WalletContext,
    secret: &str,
) -> Result<()> {
    let record = read(path)?.ok_or_else(|| anyhow!("wallet record is missing"))?;
    ensure!(&record.context == context, "wallet enrollment changed");
    ensure!(*record.sealed.open(secret)? == **key, "wallet key mismatch");
    if matches!(record.sealed, Envelope::Wallet(_)) && !has_legacy_credentials(path)? {
        return Ok(());
    }
    let record = WalletRecord {
        context: context.clone(),
        sealed: Envelope::seal(key, secret)?,
    };
    let mut conn = connection(path)?;
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE wallet_record SET record = ?1 WHERE id = 1",
        [serde_json::to_string(&record)?],
    )?;
    tx.execute_batch("DROP TABLE IF EXISTS password_record; DROP TABLE IF EXISTS passkey_record;")?;
    tx.commit()?;
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
    let json = read_optional_record(path, "wallet_record")?;
    json.map(|json| Ok(serde_json::from_str(&json)?))
        .transpose()
}

/// Detect old browser credentials without exposing an authentication route.
pub fn has_legacy_credentials(path: &Path) -> Result<bool> {
    Ok(read_optional_record(path, "password_record")?.is_some()
        || read_optional_record(path, "passkey_record")?.is_some())
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
    use crate::state::password_vault::{read_record_database, write_record_database};

    #[test]
    fn wallet_only_creation_and_legacy_migration_preserve_key() -> Result<()> {
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
        assert!(read_record_database(&path)?.is_none());
        assert_eq!(*unlock(&path, &ctx, &secret)?, *key);
        let bytes = std::fs::read(&path)?;
        assert!(create(&path, &DatabaseKey::generate()?, ctx.clone(), &secret).is_err());
        assert!(unlock(&path, &ctx, &"cd".repeat(32)).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        finish_wallet_migration(&path, &key, &ctx, &secret)?;
        assert_eq!(
            std::fs::read(&path)?,
            bytes,
            "ordinary unlock must not rewrite the envelope"
        );

        let legacy = dir.0.join("legacy.db");
        write_record_database(&legacy, &PasswordRecord::seal(&key, "legacy password")?)?;
        let old = WalletRecord {
            context: ctx.clone(),
            sealed: Envelope::Legacy(PasswordRecord::seal(&key, &secret)?),
        };
        connection(&legacy)?.execute(
            "INSERT INTO wallet_record VALUES(1, ?1)",
            [serde_json::to_string(&old)?],
        )?;
        connection(&legacy)?.execute_batch("CREATE TABLE passkey_record(id INTEGER PRIMARY KEY, record TEXT); INSERT INTO passkey_record VALUES(1, 'legacy');")?;
        let before = std::fs::read(&legacy)?;
        assert!(finish_wallet_migration(&legacy, &key, &ctx, &"cd".repeat(32)).is_err());
        assert_eq!(std::fs::read(&legacy)?, before);
        finish_wallet_migration(&legacy, &key, &ctx, &secret)?;
        assert!(!has_legacy_credentials(&legacy)?);
        assert_eq!(*unlock(&legacy, &ctx, &secret)?, *key);
        assert!(matches!(
            read(&legacy)?.expect("migrated wallet record").sealed,
            Envelope::Wallet(_)
        ));
        Ok(())
    }
}

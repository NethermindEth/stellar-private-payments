//! Wallet-derived secrets seal a random database key.
//! Only public signing context and an encrypted key envelope are persisted.

use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use serde::{Deserialize, Serialize};
use std::io::Write;
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

pub(super) fn validate_context(context: &WalletContext) -> Result<()> {
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
    // Commit the envelope before creating the database. A private temporary
    // file plus hard link installs it atomically without replacing an owner.
    let mut suffix = [0; 16];
    getrandom::getrandom(&mut suffix)?;
    let temp = path.with_extension(format!("key-{}", hex::encode(suffix)));
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        std::fs::hard_link(&temp, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(temp);
    result
}

fn read(path: &Path) -> Result<Option<WalletRecord>> {
    use std::io::Read;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && metadata.len() <= 8192,
        "invalid wallet key record"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "invalid wallet key record");
    Ok(Some(
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid wallet key record"))?,
    ))
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
    let record = read(path)?.ok_or_else(|| anyhow!("wallet unlocking is not enabled"))?;
    ensure!(
        &record.context == context,
        "wallet enrollment changed; try again"
    );
    record.sealed.open(secret)
}

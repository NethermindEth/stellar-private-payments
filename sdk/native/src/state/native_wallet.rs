//! Native storage unlocked by a Stellar CLI identity.
//! Callers must hold exclusive directory ownership through database use.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
    encrypted_migration,
    wallet_vault::{self, WalletContext},
};
use crate::{types::KeyDerivationSignature, zk::encryption::verify_owner_signature};

const ORIGIN: &str = "spp://native-storage";

pub fn record_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".key");
    path.into()
}

/// Unlock or initialize storage using an existing `stellar keys` alias.
/// Signing keys remain managed by the Stellar CLI, including its secure store.
pub fn unlock_with_stellar(
    database: &Path,
    alias: &str,
    config_dir: Option<&Path>,
) -> Result<DatabaseKey> {
    ensure!(
        !alias.is_empty()
            && !alias.starts_with('-')
            && !alias.chars().any(char::is_whitespace)
            && !(alias.len() == 56 && alias.starts_with('S')),
        "storage identity must be a Stellar CLI alias, not a secret key or seed phrase"
    );
    let run = |args: &[&str]| -> Result<Zeroizing<String>> {
        let mut command =
            Command::new(std::env::var_os("STELLAR_BIN").unwrap_or_else(|| "stellar".into()));
        command.args(args);
        if let Some(dir) = config_dir {
            command.arg("--config-dir").arg(dir);
        }
        let output = command
            .output()
            .context("run Stellar CLI; install stellar or set STELLAR_BIN")?;
        ensure!(
            output.status.success(),
            "Stellar CLI {} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Zeroizing::new(String::from_utf8(output.stdout)?);
        Ok(Zeroizing::new(output.trim().to_owned()))
    };
    let address = run(&["keys", "public-key", alias])?;
    unlock_with(database, &address, &mut |message| {
        let encoded = run(&["message", "sign", message, "--sign-with-key", alias])?;
        Ok(KeyDerivationSignature(STANDARD.decode(encoded.as_bytes())?))
    })
}

fn message(context: &WalletContext) -> String {
    format!(
        "Stellar Private Payments — unlock native encrypted database\nThis signature unlocks local storage. It does not authorize a transaction.\nDomain: spp/database-key-wrap/v1/native-wallet-signature\nOrigin: {}\nAccount: {}\nDatabase: spp.db\nSalt: {}",
        context.origin, context.address, context.salt
    )
}

fn secret(
    context: &WalletContext,
    sign: &mut impl FnMut(&str) -> Result<KeyDerivationSignature>,
) -> Result<Zeroizing<String>> {
    let message = message(context);
    let signature = sign(&message)?;
    verify_owner_signature(&context.address, &message, &signature)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&hex::decode(&context.salt)?), &signature.0)
        .expand(message.as_bytes(), key.as_mut())
        .map_err(|_| anyhow::anyhow!("cannot derive storage wrapping key"))?;
    Ok(Zeroizing::new(hex::encode(key.as_ref())))
}

fn unlock_with(
    database: &Path,
    address: &str,
    sign: &mut impl FnMut(&str) -> Result<KeyDerivationSignature>,
) -> Result<DatabaseKey> {
    let record = record_path(database);
    match fs::symlink_metadata(&record) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "wallet record must not be a symlink"
            );
            let bytes = fs::read(&record)?;
            ensure!(
                bytes.is_empty() || bytes.starts_with(b"SQLite format 3\0"),
                "unsupported legacy password record at {}; use the previous CLI to recover it or choose a new --data-dir; existing files were preserved",
                record.display()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let plaintext = encrypted_migration::is_plaintext_file(database)?;
    let nonempty = match fs::metadata(database) {
        Ok(meta) => meta.len() > 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let key = if let Some(context) = wallet_vault::context(&record)? {
        wallet_vault::validate_context(&context)?;
        ensure!(
            context.origin == ORIGIN && context.version == 1,
            "unsupported native wallet context"
        );
        ensure!(
            context.address == address,
            "storage is bound to {}; select its identity with --storage-account",
            context.address
        );
        wallet_vault::unlock(&record, &context, &secret(&context, sign)?)?
    } else {
        ensure!(
            !nonempty || plaintext,
            "encrypted database has no wallet record; restore its matching .key file or choose a new --data-dir"
        );
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)?;
        let context = WalletContext {
            version: 1,
            address: address.into(),
            origin: ORIGIN.into(),
            salt: hex::encode(salt),
        };
        let material = secret(&context, sign)?;
        ensure!(
            *material == *secret(&context, sign)?,
            "signer did not reproduce the storage signature"
        );
        let key = DatabaseKey::generate()?;
        // Create privately without replacing an existing record. SQLite commits
        // the envelope before database creation/migration, so retries reuse it.
        if !record.exists() {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            drop(options.open(&record)?);
        }
        wallet_vault::create(&record, &key, context, &material)?;
        key
    };
    if plaintext {
        eprintln!(
            "Encrypting local storage. Deleted plaintext and older backups may remain recoverable; encryption does not securely erase them."
        );
        encrypted_migration::encrypt_in_place(database, &key)?;
    } else {
        if !nonempty && database.exists() {
            fs::remove_file(database)?;
        }
        drop(SqliteStorage::connect_encrypted(
            database,
            &key,
            if nonempty {
                OpenPurpose::OpenExisting
            } else {
                OpenPurpose::CreateNew
            },
        )?);
    }
    Ok(key)
}

#[cfg(test)]
#[path = "native_wallet_tests.rs"]
mod tests;

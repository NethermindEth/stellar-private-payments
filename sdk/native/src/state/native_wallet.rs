//! Native storage unlocked by a Stellar CLI identity.
//! Callers must hold exclusive directory ownership through database use.
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
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
    let database = std::path::absolute(database)?;
    crate::stellar_cli::validate_alias("--storage-account", alias)?;
    let address = crate::stellar_cli::public_key(alias, config_dir)?;
    unlock_with(&database, &address, &mut |message| {
        crate::stellar_cli::sign_message(alias, message, config_dir)
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
    let nonempty = match fs::symlink_metadata(database) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "database must be a regular file, not a symlink or special file"
            );
            metadata.len() > 0
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let record = record_path(database);
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
            !nonempty,
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
        wallet_vault::create(&record, &key, context, &material)?;
        key
    };
    drop(futures::executor::block_on(
        SqliteStorage::connect_encrypted(
            database,
            &key,
            if nonempty {
                OpenPurpose::OpenExisting
            } else {
                OpenPurpose::CreateNew
            },
        ),
    )?);
    Ok(key)
}

#[cfg(test)]
#[path = "native_wallet_tests.rs"]
mod tests;

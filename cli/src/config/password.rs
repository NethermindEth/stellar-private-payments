//! Password-only CLI database unlocking. The SDK receives only a random key.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use serde::{Deserialize, Serialize};
use stellar_private_payments::state::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
    encrypted_migration,
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn record_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".key");
    path.into()
}

fn cipher(password: &str, salt: &[u8]) -> Result<XSalsa20Poly1305> {
    ensure!(!password.is_empty(), "storage password must not be empty");
    ensure!(salt.len() == 32, "invalid storage password salt");
    let params = Params::new(65_536, 3, 1, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid password derivation parameters"))?;
    let mut material = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, material.as_mut())
        .map_err(|_| anyhow::anyhow!("storage password derivation failed"))?;
    XSalsa20Poly1305::new_from_slice(material.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid storage wrapping key"))
}

impl Record {
    fn seal(password: &str, key: &DatabaseKey) -> Result<Self> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut salt)?;
        getrandom::getrandom(&mut nonce)?;
        let ciphertext = cipher(password, &salt)?
            .encrypt(Nonce::from_slice(&nonce), key.as_ref())
            .map_err(|_| anyhow::anyhow!("cannot wrap database key"))?;
        Ok(Self {
            version: 1,
            salt: STANDARD.encode(salt),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    fn open(&self, password: &str) -> Result<DatabaseKey> {
        ensure!(
            self.version == 1,
            "unsupported storage password record version"
        );
        let salt = STANDARD.decode(&self.salt)?;
        let nonce = STANDARD.decode(&self.nonce)?;
        let ciphertext = STANDARD.decode(&self.ciphertext)?;
        ensure!(
            nonce.len() == 24 && ciphertext.len() == 48,
            "invalid storage password record"
        );
        let bytes = Zeroizing::new(
            cipher(password, &salt)?
                .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| anyhow::anyhow!("incorrect storage password or damaged key record"))?,
        );
        Ok(DatabaseKey::new(bytes.as_slice().try_into()?))
    }
}

fn read_record(database: &Path) -> Result<Option<Record>> {
    let path = record_path(database);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 16_384,
        "invalid storage password record file"
    );
    let bytes = fs::read(&path)?;
    let record = serde_json::from_slice(&bytes).context(
        "unsupported storage key record; existing files were preserved. Restore a password-based key record or use a new --data-dir")?;
    Ok(Some(record))
}

fn read_password(file: Option<&Path>, creating: bool) -> Result<Zeroizing<String>> {
    let password = if let Some(file) = file {
        let metadata = fs::symlink_metadata(file)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 16_384,
            "storage password file must be a regular file no larger than 16 KiB"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "storage password file must have mode 600 or stricter"
            );
        }
        let mut password = Zeroizing::new(fs::read_to_string(file)?);
        if password.ends_with('\n') {
            password.pop();
            if password.ends_with('\r') {
                password.pop();
            }
        }
        password
    } else {
        let password = Zeroizing::new(rpassword::prompt_password(if creating { "Create storage password: " } else { "Storage password: " })
            .context("password prompt unavailable; use --storage-password-file for noninteractive commands")?);
        if creating {
            let repeated =
                Zeroizing::new(rpassword::prompt_password("Confirm storage password: ")?);
            ensure!(*password == *repeated, "storage passwords do not match");
        }
        password
    };
    ensure!(!password.is_empty(), "storage password must not be empty");
    Ok(password)
}

pub(super) fn unlock(database: &Path, password_file: Option<&Path>) -> Result<DatabaseKey> {
    let record = read_record(database)?;
    let password = read_password(password_file, record.is_none())?;
    unlock_with_password(database, &password, record)
}

fn unlock_with_password(
    database: &Path,
    password: &str,
    record: Option<Record>,
) -> Result<DatabaseKey> {
    let plaintext = encrypted_migration::is_plaintext_file(database)?;
    let nonempty = match fs::symlink_metadata(database) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "database must be a regular file"
            );
            metadata.len() > 0
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let key = if let Some(record) = record {
        record.open(password)?
    } else {
        if nonempty && !plaintext {
            bail!(
                "encrypted database has no password record; restore its matching .key file; existing data was preserved"
            );
        }
        let key = DatabaseKey::generate()?;
        let record = Record::seal(password, &key)?;
        let bytes = serde_json::to_vec(&record)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(record_path(database))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        key
    };
    if plaintext {
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
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).expect("password test fixture operation");
        let dir = std::env::temp_dir().join(format!(
            "spp-password-test-{}",
            STANDARD.encode(random).replace('/', "_")
        ));
        fs::create_dir(&dir).expect("password test fixture operation");
        dir
    }
    #[test]
    fn creates_reopens_and_refuses_wrong_password_without_modifying_files() {
        let dir = directory();
        let db = dir.join("spp.db");
        let key = unlock_with_password(&db, "test password", None)
            .expect("password test fixture operation");
        let original = fs::read(&db).expect("password test fixture operation");
        let metadata = fs::read(record_path(&db)).expect("password test fixture operation");
        assert!(!original.starts_with(b"SQLite format 3"));
        let reopened = unlock_with_password(
            &db,
            "test password",
            read_record(&db).expect("password test fixture operation"),
        )
        .expect("password test fixture operation");
        assert_eq!(key.as_ref(), reopened.as_ref());
        assert!(
            unlock_with_password(
                &db,
                "wrong password",
                read_record(&db).expect("password test fixture operation")
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&db).expect("password test fixture operation"),
            original
        );
        assert_eq!(
            fs::read(record_path(&db)).expect("password test fixture operation"),
            metadata
        );
        fs::remove_dir_all(dir).expect("password test fixture operation");
    }
    #[test]
    fn interrupted_creation_reuses_saved_key() {
        let dir = directory();
        let db = dir.join("spp.db");
        let key = DatabaseKey::generate().expect("password test fixture operation");
        fs::write(
            record_path(&db),
            serde_json::to_vec(
                &Record::seal("password", &key).expect("password test fixture operation"),
            )
            .expect("password test fixture operation"),
        )
        .expect("password test fixture operation");
        let reopened = unlock_with_password(
            &db,
            "password",
            read_record(&db).expect("password test fixture operation"),
        )
        .expect("password test fixture operation");
        assert_eq!(key.as_ref(), reopened.as_ref());
        fs::remove_dir_all(dir).expect("password test fixture operation");
    }
    #[test]
    fn unsupported_record_and_empty_password_preserve_data() {
        let dir = directory();
        let db = dir.join("spp.db");
        fs::write(record_path(&db), b"unsupported").expect("password test fixture operation");
        assert!(read_record(&db).is_err());
        assert!(!db.exists());
        assert!(
            Record::seal(
                "",
                &DatabaseKey::generate().expect("password test fixture operation")
            )
            .is_err()
        );
        fs::remove_dir_all(dir).expect("password test fixture operation");
    }
}

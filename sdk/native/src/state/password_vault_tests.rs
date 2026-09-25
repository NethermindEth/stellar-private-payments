use super::*;
use crate::state::{
    SqliteStorage,
    database_key::{DatabaseKeyProvider, OpenPurpose},
};
use std::{fs, path::PathBuf};

const PASSWORD: &str = "correct horse battery staple";
const OTHER_PASSWORD: &str = "a different long password";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self> {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = std::env::temp_dir().join(format!("spp-password-test-{}", hex::encode(suffix)));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn provider(f: &Fixture, password: &str) -> PasswordKeyProvider {
    PasswordKeyProvider::new(f.db(), Zeroizing::new(password.to_owned()))
}

#[test]
fn sealed_key_opens_only_with_its_password() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let record = PasswordRecord::seal(&key, PASSWORD)?;
    assert_eq!(*record.open(PASSWORD)?, *key);
    assert_eq!(
        record.open(OTHER_PASSWORD).err(),
        Some(VaultError::WrongPassword)
    );
    // Passwords are not trimmed: surrounding whitespace is part of them.
    assert_eq!(
        record.open(&format!(" {PASSWORD}")).err(),
        Some(VaultError::WrongPassword)
    );
    Ok(())
}

#[test]
fn record_keeps_neither_password_nor_key() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let json = PasswordRecord::seal(&key, PASSWORD)?.to_json()?;
    assert!(!json.contains(PASSWORD));
    assert!(!json.contains(&STANDARD.encode(key.as_ref())));
    assert!(!json.contains(&hex::encode(key.as_ref())));
    Ok(())
}

#[test]
fn changing_the_password_keeps_the_database_key() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let old = PasswordRecord::seal(&key, PASSWORD)?;
    let new = PasswordRecord::seal(&old.open(PASSWORD)?, OTHER_PASSWORD)?;
    assert_eq!(*new.open(OTHER_PASSWORD)?, *key);
    assert_eq!(new.open(PASSWORD).err(), Some(VaultError::WrongPassword));
    Ok(())
}

#[test]
fn new_passwords_follow_the_length_policy() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let short = "x".repeat(MIN_PASSWORD_CHARS - 1);
    assert_eq!(
        validate_new_password(&short),
        Err(VaultError::PasswordTooShort)
    );
    // The minimum counts characters, not bytes.
    assert_eq!(
        validate_new_password(&"ć".repeat(MIN_PASSWORD_CHARS - 1)),
        Err(VaultError::PasswordTooShort)
    );
    assert!(validate_new_password(&"ć".repeat(MIN_PASSWORD_CHARS)).is_ok());
    assert_eq!(
        validate_new_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)),
        Err(VaultError::PasswordTooLong)
    );
    assert!(PasswordRecord::seal(&key, &short).is_err());
    Ok(())
}

#[test]
fn damaged_records_are_rejected() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let record = PasswordRecord::seal(&key, PASSWORD)?;

    let mut sealed = STANDARD.decode(&record.sealed_key)?;
    sealed[0] ^= 1;
    let flipped = PasswordRecord {
        sealed_key: STANDARD.encode(sealed),
        ..record.clone()
    };
    assert_eq!(
        flipped.open(PASSWORD).err(),
        Some(VaultError::WrongPassword)
    );

    let greedy = PasswordRecord {
        kdf: Kdf {
            memory_kib: MAX_MEMORY_KIB + 1,
            ..record.kdf.clone()
        },
        ..record.clone()
    };
    assert_eq!(greedy.open(PASSWORD).err(), Some(VaultError::InvalidRecord));

    let future = PasswordRecord {
        version: RECORD_VERSION + 1,
        ..record.clone()
    };
    assert_eq!(future.open(PASSWORD).err(), Some(VaultError::InvalidRecord));

    let json = record.to_json()?;
    assert_eq!(PasswordRecord::from_json(&json)?, record);
    let extra = json.replacen('{', "{\"extra\":1,", 1);
    assert_eq!(
        PasswordRecord::from_json(&extra),
        Err(VaultError::InvalidRecord)
    );
    Ok(())
}

#[test]
fn production_parameters_derive_a_key() -> Result<()> {
    let key = DatabaseKey::generate()?;
    let record =
        PasswordRecord::seal_with(&key, PASSWORD, Kdf::generate_with(MEMORY_KIB, ITERATIONS)?)?;
    assert_eq!(record.kdf.memory_kib, 64 * 1024);
    assert_eq!(*record.open(PASSWORD)?, *key);
    Ok(())
}

#[test]
fn provider_creates_record_then_database_and_reopens_it() -> Result<()> {
    let f = Fixture::new()?;
    let key = futures::executor::block_on(
        provider(&f, PASSWORD).acquire("test", OpenPurpose::CreateNew),
    )?;
    assert!(record_path(&f.db()).is_file());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(record_path(&f.db()))?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let mut storage = SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::CreateNew)?;
    storage.set_setting_json("marker", &"kept")?;
    drop(storage);

    let reopened = futures::executor::block_on(
        provider(&f, PASSWORD).acquire("test", OpenPurpose::OpenExisting),
    )?;
    assert_eq!(
        SqliteStorage::connect_encrypted(f.db(), &reopened, OpenPurpose::OpenExisting)?
            .get_setting_json::<String>("marker")?
            .as_deref(),
        Some("kept")
    );
    Ok(())
}

#[test]
fn provider_rejects_wrong_password_and_existing_database() -> Result<()> {
    let f = Fixture::new()?;
    let key = futures::executor::block_on(
        provider(&f, PASSWORD).acquire("test", OpenPurpose::CreateNew),
    )?;
    drop(SqliteStorage::connect_encrypted(
        f.db(),
        &key,
        OpenPurpose::CreateNew,
    )?);
    let record = fs::read(record_path(&f.db()))?;

    let wrong = futures::executor::block_on(
        provider(&f, OTHER_PASSWORD).acquire("test", OpenPurpose::OpenExisting),
    );
    assert_eq!(
        wrong.err().and_then(|e| e.downcast::<VaultError>().ok()),
        Some(VaultError::WrongPassword)
    );

    // Creating over an existing database must not replace its record.
    assert!(
        futures::executor::block_on(
            provider(&f, OTHER_PASSWORD).acquire("test", OpenPurpose::CreateNew)
        )
        .is_err()
    );
    assert_eq!(fs::read(record_path(&f.db()))?, record);
    Ok(())
}

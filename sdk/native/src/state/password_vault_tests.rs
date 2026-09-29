use super::*;
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
fn replacing_record_does_not_follow_preplanted_temporary_symlink() -> Result<()> {
    let f = Fixture::new()?;
    let path = record_path(&f.db());
    let victim = f.0.join("victim");
    fs::write(&victim, b"must survive")?;
    let mut old_temporary = path.as_os_str().to_owned();
    old_temporary.push(".tmp");
    std::os::unix::fs::symlink(&victim, std::path::PathBuf::from(old_temporary))?;
    let key = DatabaseKey::generate()?;
    write_record(&path, &PasswordRecord::seal(&key, PASSWORD)?)?;
    write_record(&path, &PasswordRecord::seal(&key, OTHER_PASSWORD)?)?;
    assert_eq!(fs::read(&victim)?, b"must survive");
    assert_eq!(
        *PasswordRecord::from_json(&fs::read_to_string(path)?)?.open(OTHER_PASSWORD)?,
        *key
    );
    Ok(())
}

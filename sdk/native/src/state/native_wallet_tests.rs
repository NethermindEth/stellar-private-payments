use super::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self> {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = std::env::temp_dir().join(format!("spp-native-wallet-{}", hex::encode(suffix)));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn db(&self) -> PathBuf {
        self.0.join("spp.db")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn address() -> String {
    stellar_strkey::ed25519::PublicKey(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned()
}
fn sign(message: &str) -> Result<KeyDerivationSignature> {
    let digest = Sha256::digest(crate::zk::encryption::sep53_payload(message));
    Ok(KeyDerivationSignature(
        SigningKey::from_bytes(&[7; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec(),
    ))
}
fn open(path: &Path, key: &DatabaseKey) -> Result<SqliteStorage> {
    SqliteStorage::connect_encrypted(path, key, OpenPurpose::OpenExisting)
}
#[test]
fn creates_encrypted_storage_and_unlocks_after_restart() -> Result<()> {
    let f = Fixture::new()?;
    let mut calls = 0;
    let key = unlock_with(&f.db(), &address(), &mut |message| {
        calls += 1;
        sign(message)
    })?;
    assert_eq!(calls, 2);
    open(&f.db(), &key)?.set_setting_json("test", &"private marker")?;
    assert!(!encrypted_migration::is_plaintext_file(&f.db())?);
    assert!(
        !fs::read(f.db())?
            .windows(14)
            .any(|w| w == b"private marker")
    );
    let record = fs::read(record_path(&f.db()))?;
    let recovered = unlock_with(&f.db(), &address(), &mut |message| {
        calls += 1;
        sign(message)
    })?;
    assert_eq!(calls, 3);
    assert_eq!(*key, *recovered);
    assert_eq!(
        open(&f.db(), &recovered)?.get_setting_json::<String>("test")?,
        Some("private marker".into())
    );
    assert_eq!(record, fs::read(record_path(&f.db()))?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(record_path(&f.db()))?.permissions().mode() & 0o777,
            0o600
        );
    }
    Ok(())
}
#[test]
fn rejected_signing_and_wrong_identity_preserve_storage() -> Result<()> {
    let f = Fixture::new()?;
    assert!(unlock_with(&f.db(), &address(), &mut |_| anyhow::bail!("cancelled")).is_err());
    assert!(!record_path(&f.db()).exists());
    assert!(!f.db().exists());
    unlock_with(&f.db(), &address(), &mut sign)?;
    let before = fs::read(f.db())?;
    let record = fs::read(record_path(&f.db()))?;
    assert!(unlock_with(&f.db(), "another account", &mut |_| panic!("must not sign")).is_err());
    assert!(
        unlock_with(&f.db(), &address(), &mut |_| Ok(KeyDerivationSignature(
            vec![0; 64]
        )))
        .is_err()
    );
    assert_eq!(before, fs::read(f.db())?);
    assert_eq!(record, fs::read(record_path(&f.db()))?);
    Ok(())
}
#[test]
fn interrupted_creation_reuses_record_for_missing_and_empty_database() -> Result<()> {
    let f = Fixture::new()?;
    let key = unlock_with(&f.db(), &address(), &mut sign)?;
    fs::rename(f.db(), f.0.join("backup.db"))?;
    let record = fs::read(record_path(&f.db()))?;
    for empty in [false, true] {
        if empty {
            fs::write(f.db(), [])?;
        }
        let recovered = unlock_with(&f.db(), &address(), &mut sign)?;
        assert_eq!(*key, *recovered);
        assert_eq!(record, fs::read(record_path(&f.db()))?);
        drop(open(&f.0.join("backup.db"), &recovered)?);
        fs::remove_file(f.db())?;
    }
    Ok(())
}
#[test]
fn failed_migration_preserves_plaintext_and_retries_with_saved_record() -> Result<()> {
    let f = Fixture::new()?;
    let legacy = rusqlite::Connection::open(f.db())?;
    legacy.execute_batch(include_str!("schema.sql"))?;
    legacy.execute(
        "INSERT INTO app_settings (key, value) VALUES ('test', ?1)",
        ["\"preserved\""],
    )?;
    legacy.pragma_update(None, "user_version", 2)?;
    drop(legacy);
    // Simulate a filesystem failure before the staging database can be created.
    fs::create_dir(f.0.join("spp.db.encrypting"))?;
    let plaintext = fs::read(f.db())?;
    assert!(unlock_with(&f.db(), &address(), &mut sign).is_err());
    assert_eq!(plaintext, fs::read(f.db())?);
    let record = fs::read(record_path(&f.db()))?;
    let context = wallet_vault::context(&record_path(&f.db()))?
        .expect("failed migration retains wallet context");
    let saved = wallet_vault::unlock(
        &record_path(&f.db()),
        &context,
        &secret(&context, &mut sign)?,
    )?;
    fs::remove_dir(f.0.join("spp.db.encrypting"))?;
    let recovered = unlock_with(&f.db(), &address(), &mut sign)?;
    assert_eq!(*saved, *recovered);
    assert_eq!(record, fs::read(record_path(&f.db()))?);
    assert_eq!(
        open(&f.db(), &recovered)?.get_setting_json::<String>("test")?,
        Some("preserved".into())
    );
    assert!(!encrypted_migration::is_plaintext_file(&f.db())?);
    Ok(())
}
#[test]
fn missing_and_invalid_records_never_replace_encrypted_data() -> Result<()> {
    let f = Fixture::new()?;
    unlock_with(&f.db(), &address(), &mut sign)?;
    let before = fs::read(f.db())?;
    fs::remove_file(record_path(&f.db()))?;
    assert!(unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign")).is_err());
    assert_eq!(before, fs::read(f.db())?);
    let invalid = b"not a SQLite wallet key record";
    fs::write(record_path(&f.db()), invalid)?;
    assert!(
        unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign"))
            .expect_err("invalid wallet key records must be refused")
            .to_string()
            .contains("invalid wallet key record")
    );
    assert_eq!(invalid, fs::read(record_path(&f.db()))?.as_slice());
    assert_eq!(before, fs::read(f.db())?);
    Ok(())
}
#[test]
fn rejects_record_symlinks() -> Result<()> {
    #[cfg(unix)]
    {
        let f = Fixture::new()?;
        let victim = f.0.join("victim");
        fs::write(&victim, "preserve")?;
        std::os::unix::fs::symlink(&victim, record_path(&f.db()))?;
        assert!(unlock_with(&f.db(), &address(), &mut sign).is_err());
        assert_eq!(fs::read_to_string(victim)?, "preserve");
    }
    Ok(())
}

#[test]
fn rejects_directories_before_signing_or_creating_files() -> Result<()> {
    for record in [false, true] {
        let f = Fixture::new()?;
        let path = if record { record_path(&f.db()) } else { f.db() };
        fs::create_dir(&path)?;
        let error = unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign"))
            .expect_err("directories must be rejected");
        assert!(error.to_string().contains("regular file"));
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(&f.0)?.count(), 1);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_database_symlinks_without_replacing_links_or_plaintext_targets() -> Result<()> {
    for exists in [false, true] {
        let f = Fixture::new()?;
        let target = f.0.join("target.db");
        if exists {
            let conn = rusqlite::Connection::open(&target)?;
            conn.execute_batch(
                "CREATE TABLE secret(value TEXT); INSERT INTO secret VALUES ('preserve');",
            )?;
        }
        let before = if exists {
            Some(fs::read(&target)?)
        } else {
            None
        };
        std::os::unix::fs::symlink(&target, f.db())?;
        let error = unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign"))
            .expect_err("database symlinks must be rejected");
        assert!(error.to_string().contains("regular file"));
        assert_eq!(fs::read_link(f.db())?, target);
        assert!(!record_path(&f.db()).exists());
        assert_eq!(fs::read(&target).ok(), before);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_special_files_before_reading_or_signing() -> Result<()> {
    for record in [false, true] {
        let f = Fixture::new()?;
        let path = if record { record_path(&f.db()) } else { f.db() };
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()?
                .success()
        );
        let error = unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign"))
            .expect_err("special files must be rejected");
        assert!(error.to_string().contains("regular file"));
        assert_eq!(fs::read_dir(&f.0)?.count(), 1);
    }
    Ok(())
}

#[test]
fn rejects_short_and_large_non_sqlite_records_without_modification() -> Result<()> {
    for size in [1, 15, 16, 16 * 1024 * 1024] {
        let f = Fixture::new()?;
        let record = record_path(&f.db());
        fs::File::create(&record)?.set_len(size)?;
        let error = unlock_with(&f.db(), &address(), &mut |_| panic!("must not sign"))
            .expect_err("non-SQLite records must be rejected");
        assert!(error.to_string().contains("invalid wallet key record"));
        assert_eq!(fs::metadata(&record)?.len(), size);
        assert!(!f.db().exists());
    }
    Ok(())
}

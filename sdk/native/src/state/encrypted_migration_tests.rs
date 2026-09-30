use super::*;
use crate::state::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self> {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = std::env::temp_dir().join(format!("spp-migration-test-{}", hex::encode(suffix)));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn db(&self) -> PathBuf {
        self.0.join("spp.db")
    }

    fn staging(&self) -> PathBuf {
        self.0.join("spp.db.encrypting")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A plaintext database with settings and rows in an AUTOINCREMENT table, so
/// `sqlite_sequence` has to be carried over too.
fn seed_plaintext(path: &std::path::Path) -> Result<()> {
    let mut storage = crate::state::test_plaintext_storage(path)?;
    storage.set_setting_json("explorer", &"https://example.test")?;
    drop(storage);
    let conn = Connection::open(path)?;
    for amount in ["1", "2", "3"] {
        conn.execute(
            "INSERT INTO app_user_operations (address, pool_contract_id, op_type, amount, \
             direction) VALUES ('GADDRESS', 'CPOOL', 'deposit', ?1, 'in')",
            [amount],
        )?;
    }
    conn.execute("DELETE FROM app_user_operations WHERE amount = '3'", [])?;
    Ok(())
}

#[test]
fn encrypts_in_place_and_keeps_every_row() -> Result<()> {
    let f = Fixture::new()?;
    seed_plaintext(&f.db())?;
    let before = fingerprint(&Connection::open(f.db())?)?;
    assert!(is_plaintext_file(&f.db())?);

    let key = DatabaseKey::generate()?;
    encrypt_in_place(&f.db(), &key)?;

    assert!(!is_plaintext_file(&f.db())?);
    assert!(!f.staging().exists());
    let bytes = fs::read(f.db())?;
    assert!(!bytes.windows(20).any(|w| w == b"https://example.test"));

    let conn = super::super::database_key::open(&f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(fingerprint(&conn)?, before);
    // The next AUTOINCREMENT id continues after the deleted row, as in the
    // source.
    conn.execute(
        "INSERT INTO app_user_operations (address, pool_contract_id, op_type, amount, \
         direction) VALUES ('GADDRESS', 'CPOOL', 'deposit', '4', 'in')",
        [],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM app_user_operations WHERE amount = '4'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(id, 4);
    drop(conn);

    let storage = SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        storage.get_setting_json::<String>("explorer")?.as_deref(),
        Some("https://example.test")
    );
    Ok(())
}

#[test]
fn discards_a_partial_copy_from_an_interrupted_run() -> Result<()> {
    let f = Fixture::new()?;
    seed_plaintext(&f.db())?;
    fs::write(f.staging(), b"partial copy from a crashed run")?;
    let key = DatabaseKey::generate()?;
    encrypt_in_place(&f.db(), &key)?;
    assert!(!f.staging().exists());
    assert!(SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting).is_ok());
    Ok(())
}

#[test]
fn a_failed_run_leaves_the_plaintext_database_untouched() -> Result<()> {
    let f = Fixture::new()?;
    seed_plaintext(&f.db())?;
    let before = fs::read(f.db())?;
    // A directory where the copy should go makes the run fail before it
    // touches the source.
    fs::create_dir(f.staging())?;
    assert!(encrypt_in_place(&f.db(), &DatabaseKey::generate()?).is_err());
    assert_eq!(fs::read(f.db())?, before);
    Ok(())
}

#[test]
fn refuses_databases_that_are_not_plaintext() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    drop(SqliteStorage::connect_encrypted(
        f.db(),
        &key,
        OpenPurpose::CreateNew,
    )?);
    let before = fs::read(f.db())?;
    assert!(encrypt_in_place(&f.db(), &key).is_err());
    assert_eq!(fs::read(f.db())?, before);
    assert!(encrypt_in_place(&f.0.join("missing.db"), &key).is_err());
    Ok(())
}

#[test]
fn an_interrupted_copy_is_recognised_and_can_be_redone() -> Result<()> {
    let f = Fixture::new()?;
    seed_plaintext(&f.db())?;
    let before = fingerprint(&Connection::open(f.db())?)?;
    let encrypted = f.0.join("spp.encrypted.db");
    let key = DatabaseKey::generate()?;

    // An interrupted copy leaves an encrypted database without pages.
    drop(super::super::database_key::open(
        &encrypted,
        &key,
        OpenPurpose::CreateNew,
    )?);
    assert!(!has_tables(&encrypted, &key)?);

    fs::remove_file(&encrypted)?;
    copy_into_encrypted(&f.db(), None, &encrypted, &key)?;
    assert!(has_tables(&encrypted, &key)?);
    assert!(has_tables(&encrypted, &DatabaseKey::generate()?).is_err());
    let conn = super::super::database_key::open(&encrypted, &key, OpenPurpose::OpenExisting)?;
    assert_eq!(fingerprint(&conn)?, before);
    drop(conn);

    // A copy never overwrites an existing database.
    assert!(copy_into_encrypted(&f.db(), None, &encrypted, &key).is_err());
    Ok(())
}

#[test]
fn migrates_analyzed_database_without_copying_optimizer_statistics() -> Result<()> {
    let f = Fixture::new()?;
    seed_plaintext(&f.db())?;
    let conn = Connection::open(f.db())?;
    conn.execute_batch("ANALYZE")?;
    let stats: i64 = conn.query_row("SELECT count(*) FROM sqlite_stat1", [], |row| row.get(0))?;
    assert!(stats > 0);
    let before = fingerprint(&conn)?;
    drop(conn);
    let key = DatabaseKey::generate()?;
    encrypt_in_place(&f.db(), &key)?;
    let conn = super::super::database_key::open(&f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(fingerprint(&conn)?, before);
    conn.execute_batch("ANALYZE")?;
    assert_eq!(fingerprint(&conn)?, before);
    Ok(())
}

#[test]
fn browser_copy_preserves_legacy_version_and_native_encryption_migrates_it() -> Result<()> {
    let f = Fixture::new()?;
    let source = Connection::open(f.db())?;
    source.execute_batch(include_str!("schema.sql"))?;
    source.pragma_update(None, "user_version", 1)?;
    source.execute(
        "INSERT INTO app_settings VALUES ('private-marker','\"retained\"')",
        [],
    )?;
    drop(source);
    let key = DatabaseKey::generate()?;
    let copied = f.0.join("browser-copy.db");
    copy_into_encrypted(&f.db(), None, &copied, &key)?;
    let conn = super::super::database_key::open(&copied, &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
        1
    );
    assert!(
        conn.prepare("SELECT gvk_ciphertext FROM pool_commitments")
            .is_err()
    );
    drop(conn);
    encrypt_in_place(&f.db(), &key)?;
    let storage = SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        storage
            .conn
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
        2
    );
    assert!(
        storage
            .conn
            .prepare("SELECT gvk_ciphertext FROM pool_commitments")
            .is_ok()
    );
    assert_eq!(
        storage
            .get_setting_json::<String>("private-marker")?
            .as_deref(),
        Some("retained")
    );
    Ok(())
}

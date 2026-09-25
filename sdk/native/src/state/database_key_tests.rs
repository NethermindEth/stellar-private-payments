use super::*;
use crate::{LocalStorage, Storage as StorageTrait, state::SqliteStorage};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self> {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = std::env::temp_dir().join(format!("spp-encrypted-test-{}", hex::encode(suffix)));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this test's exclusively created synthetic directory is removed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

const MARKER: &str = "ENCRYPTED_STORAGE_TEST_PROTECTED_1ce596";

#[test]
fn encrypted_filenames_remain_literal() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    for name in [
        "spaces #percent%?mode=memory.db",
        "file:literal.db",
        "unicode-ć.db",
    ] {
        let path = f.0.join(name);
        seed(&path, &key)?;
        let before = fs::read(&path)?;
        assert!(
            SqliteStorage::connect_encrypted(
                &path,
                &DatabaseKey::generate()?,
                OpenPurpose::OpenExisting
            )
            .is_err()
        );
        assert_eq!(fs::read(&path)?, before);
        assert_eq!(
            SqliteStorage::connect_encrypted(&path, &key, OpenPurpose::OpenExisting)?
                .get_setting_json::<String>("protected")?
                .as_deref(),
            Some(MARKER)
        );
    }
    Ok(())
}

fn seed(path: &Path, key: &DatabaseKey) -> Result<()> {
    let mut storage = SqliteStorage::connect_encrypted(path, key, OpenPurpose::CreateNew)?;
    storage.set_setting_json("protected", &MARKER)?;
    for i in 0..32 {
        storage.set_setting_json(&format!("large-{i}"), &MARKER.repeat(150))?;
    }
    Ok(())
}

fn snapshot(path: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut entries = vec![];
    let parent = path.parent().expect("fixture parent");
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            entries.push((entry.path(), fs::read(entry.path())?));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

#[test]
fn encrypted_create_reopen_preserves_schema_and_hides_contents() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    seed(&f.db(), &key)?;
    assert_eq!(fs::metadata(f.db())?.permissions().mode() & 0o777, 0o600);
    let bytes = fs::read(f.db())?;
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()));
    assert!(!bytes.windows(32).any(|w| w == key.as_ref()));
    let reopened = SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        reopened.get_setting_json::<String>("protected")?.as_deref(),
        Some(MARKER)
    );
    drop(reopened);
    let conn = open(&f.db(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
        2
    );
    assert_eq!(
        conn.pragma_query_value(None, "temp_store", |r| r.get::<_, i64>(0))?,
        2
    );
    assert_eq!(
        conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
        "ok"
    );
    assert!(conn.query_row(
        "SELECT sqlite_compileoption_used('TEMP_STORE=3')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}

#[test]
fn wrong_or_missing_key_preserves_clean_and_hot_database() -> Result<()> {
    for hot in [false, true] {
        let f = Fixture::new()?;
        let key = DatabaseKey::generate()?;
        seed(&f.db(), &key)?;
        if hot {
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "state::database_key::tests::crash_writer",
                    "--nocapture",
                ])
                .env("SPP_TEST_CRASH_DB", f.db())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .as_mut()
                .expect("child stdin")
                .write_all(key.as_ref())?;
            let mut output = BufReader::new(child.stdout.take().expect("child stdout"));
            let mut ready = false;
            for line in (&mut output).lines() {
                if line?.ends_with("crash-ready") {
                    ready = true;
                    break;
                }
            }
            // Kill only the child spawned above to leave its synthetic hot
            // journal.
            let _ = child.kill();
            child.wait()?;
            assert!(ready, "crash writer failed before opening its transaction");
            assert!(f.0.join("state.db-journal").exists());
        }
        let before = snapshot(&f.db())?;
        assert!(
            SqliteStorage::connect_encrypted(
                f.db(),
                &DatabaseKey::generate()?,
                OpenPurpose::OpenExisting
            )
            .is_err()
        );
        assert_eq!(before, snapshot(&f.db())?);
        assert!(SqliteStorage::connect_file(f.db()).is_err());
        assert_eq!(before, snapshot(&f.db())?);
        let recovered = SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting)?;
        assert_eq!(
            recovered.get_setting_json::<String>("large-0")?,
            Some(MARKER.repeat(150))
        );
    }
    Ok(())
}

#[test]
#[ignore = "child process helper for a deliberate interrupted transaction"]
fn crash_writer() -> Result<()> {
    // `cargo test -- --ignored` also runs this helper directly; only the
    // parent test sets the database path.
    let Some(path) = std::env::var_os("SPP_TEST_CRASH_DB") else {
        return Ok(());
    };
    let path = PathBuf::from(path);
    let mut key = DatabaseKey::new([0; 32]);
    std::io::stdin().read_exact(&mut key[..])?;
    let conn = open(&path, &key, OpenPurpose::OpenExisting)?;
    conn.execute_batch("PRAGMA cache_size=5; BEGIN IMMEDIATE; UPDATE app_settings SET value=json_object('pending',hex(zeroblob(4096))) WHERE key LIKE 'large-%'")?;
    println!("crash-ready");
    std::io::stdout().flush()?;
    std::io::stdin().read_exact(&mut [0; 1])?;
    anyhow::bail!("crash helper must be killed with an uncommitted transaction")
}

#[test]
fn create_and_open_purposes_are_exclusive() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    assert!(SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting).is_err());
    assert!(!f.db().exists());
    seed(&f.db(), &key)?;
    let before = snapshot(&f.db())?;
    assert!(SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::CreateNew).is_err());
    assert_eq!(before, snapshot(&f.db())?);
    Ok(())
}

struct Provider<'a>(&'a DatabaseKey);
#[async_trait::async_trait(?Send)]
impl DatabaseKeyProvider for Provider<'_> {
    async fn acquire(&self, _id: &str, _purpose: OpenPurpose) -> Result<DatabaseKey> {
        Ok(DatabaseKey::new(**self.0))
    }
}
struct Unavailable;
#[async_trait::async_trait(?Send)]
impl DatabaseKeyProvider for Unavailable {
    async fn acquire(&self, _id: &str, _purpose: OpenPurpose) -> Result<DatabaseKey> {
        anyhow::bail!("provider unavailable")
    }
}

#[test]
fn provider_failure_and_threaded_forks() -> Result<()> {
    let f = Fixture::new()?;
    let path = f.db();
    let path = path.to_str().expect("UTF-8 temp directory");
    assert!(
        futures::executor::block_on(LocalStorage::open_with_key_provider(
            path,
            "test",
            OpenPurpose::CreateNew,
            &Unavailable
        ))
        .is_err()
    );
    assert!(!f.db().exists());
    let key = DatabaseKey::generate()?;
    let storage = futures::executor::block_on(LocalStorage::open_with_key_provider(
        path,
        "test",
        OpenPurpose::CreateNew,
        &Provider(&key),
    ))?;
    storage
        .storage_mut()
        .set_setting_json("protected", &MARKER)?;
    let fork = storage.fork()?;
    drop(storage);
    let value = std::thread::spawn(move || fork.storage().get_setting_json::<String>("protected"))
        .join()
        .expect("fork thread")?;
    assert_eq!(value.as_deref(), Some(MARKER));
    Ok(())
}

#[test]
fn forks_open_while_another_fork_commits() -> Result<()> {
    let f = Fixture::new()?;
    let path = f.db();
    let path = path.to_str().expect("UTF-8 temp directory");
    let key = DatabaseKey::generate()?;
    let storage = futures::executor::block_on(LocalStorage::open_with_key_provider(
        path,
        "test",
        OpenPurpose::CreateNew,
        &Provider(&key),
    ))?;
    let writer = storage.fork()?;
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writing = done.clone();
    let handle = std::thread::spawn(move || -> Result<()> {
        let mut i = 0u32;
        while !writing.load(std::sync::atomic::Ordering::Relaxed) {
            writer
                .storage_mut()
                .set_setting_json(&format!("large-{}", i % 8), &MARKER.repeat(400))?;
            i = i.wrapping_add(1);
        }
        Ok(())
    });
    let forked = (0..300).try_for_each(|_| storage.fork().map(drop));
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    handle.join().expect("writer thread")?;
    forked?;
    Ok(())
}

#[test]
fn corrupt_ciphertext_is_rejected_without_changes() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    seed(&f.db(), &key)?;
    let mut bytes = fs::read(f.db())?;
    bytes[100] ^= 0x80;
    fs::write(f.db(), &bytes)?;
    assert!(SqliteStorage::connect_encrypted(f.db(), &key, OpenPurpose::OpenExisting).is_err());
    assert_eq!(fs::read(f.db())?, bytes);
    Ok(())
}

#[test]
fn key_debug_is_redacted_and_plaintext_remains_usable() -> Result<()> {
    let key = DatabaseKey::generate()?;
    assert_eq!(format!("{key:?}"), "DatabaseKey([REDACTED])");
    assert_ne!(*key, [0; 32]);
    let f = Fixture::new()?;
    let mut plain = SqliteStorage::connect_file(f.db())?;
    plain.set_setting_json("plain", &"legacy")?;
    drop(plain);
    assert!(fs::read(f.db())?.starts_with(b"SQLite format 3"));
    assert_eq!(
        SqliteStorage::connect_existing_plaintext(f.db())?
            .get_setting_json::<String>("plain")?
            .as_deref(),
        Some("legacy")
    );
    Ok(())
}

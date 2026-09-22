use super::*;
use crate::state::{
    SqliteStorage,
    database_key::{self, DatabaseKey, OpenPurpose},
};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MARKER: &str = "MIGRATION_PROTECTED_SYNTHETIC_43a18f";

struct Fixture(PathBuf);
impl Fixture {
    fn new(version: i64) -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)?;
        let root = std::env::temp_dir().join(format!("spp-migration-{}", hex::encode(random)));
        fs::create_dir(&root)?;
        let fixture = Self(root);
        let db = Connection::open(fixture.source())?;
        db.execute_batch(include_str!("../schema.sql"))?;
        if version == 2 {
            db.execute_batch(include_str!("../schema_v2_gvk_ciphertext.sql"))?;
        }
        db.pragma_update(None, "user_version", version)?;
        db.pragma_update(None, "application_id", 92341)?;
        db.execute(
            "INSERT INTO app_settings(rowid,key,value) VALUES(91,'protected',?1)",
            [serde_json::to_string(MARKER)?],
        )?;
        db.execute("INSERT INTO contracts VALUES(12,'test-contract')", [])?;
        db.execute("INSERT INTO accounts VALUES(19,'test-owner')", [])?;
        db.execute(
            "INSERT INTO keypairs VALUES(21,?1,?1,?1,?1,?1,19)",
            [MARKER.as_bytes()],
        )?;
        // Exercise a sequence value larger than any currently existing row.
        db.execute(
            "INSERT INTO sqlite_sequence(name,seq) VALUES('app_user_operations',900)",
            [],
        )?;
        Ok(fixture)
    }
    fn source(&self) -> PathBuf {
        self.0.join("source.db")
    }
    fn migration(&self) -> PathBuf {
        self.0.join("migration")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn owned(key: &DatabaseKey) -> DatabaseKey {
    DatabaseKey::new(**key)
}

fn bytes(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            result.extend(bytes(&entry.path())?);
        } else {
            result.push((entry.path(), fs::read(entry.path())?));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

fn no_plaintext(root: &Path) -> Result<()> {
    for (_, file) in bytes(root)? {
        assert!(!file.starts_with(b"SQLite format 3\0"));
        assert!(
            !file
                .windows(MARKER.len())
                .any(|part| part == MARKER.as_bytes())
        );
    }
    Ok(())
}

#[test]
fn migrate_both_schema_versions_preserves_data_and_post_activation_writes() -> Result<()> {
    for version in [1, 2] {
        let f = Fixture::new(version)?;
        let key = DatabaseKey::generate()?;
        let original = fs::read(f.source())?;
        let mut migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
        assert_eq!(migration.status()?, MigrationStatus::Copying);
        assert_eq!(migration.selected_path()?, f.source());
        migration.prepare()?;
        assert_eq!(migration.status()?, MigrationStatus::Prepared);
        assert_eq!(fs::read(f.source())?, original);
        no_plaintext(&f.migration())?;
        drop(migration);
        let mut migration = NativeMigration::open(f.migration(), owned(&key))?;
        migration.activate()?;
        let path = migration.selected_path()?;
        let c = database_key::open(&path, &key, OpenPurpose::OpenExisting)?;
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            c.pragma_query_value(None, "application_id", |r| r.get::<_, i64>(0))?,
            92341
        );
        assert_eq!(
            c.query_row(
                "SELECT rowid FROM app_settings WHERE key='protected'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            91
        );
        assert_eq!(
            c.query_row(
                "SELECT seq FROM sqlite_sequence WHERE name='app_user_operations'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            900
        );
        assert_eq!(
            c.query_row("SELECT note_private_key FROM keypairs", [], |r| r
                .get::<_, Vec<u8>>(0))?,
            MARKER.as_bytes()
        );
        drop(c);
        let mut storage = SqliteStorage::connect_encrypted(&path, &key, OpenPurpose::OpenExisting)?;
        assert_eq!(
            storage.get_setting_json::<String>("protected")?.as_deref(),
            Some(MARKER)
        );
        storage.set_setting_json("after-activation", &true)?;
        drop(storage);
        assert!(migration.abort().is_err());
        assert_eq!(fs::read(f.source())?, original);
        drop(migration);
        let mut migration = NativeMigration::open(f.migration(), owned(&key))?;
        migration.finish()?;
        migration.finish()?;
        assert_eq!(migration.status()?, MigrationStatus::Complete);
        assert!(!f.source().exists());
        let storage = SqliteStorage::connect_encrypted(
            migration.selected_path()?,
            &key,
            OpenPurpose::OpenExisting,
        )?;
        assert_eq!(
            storage.get_setting_json::<bool>("after-activation")?,
            Some(true)
        );
        drop(storage);
        drop(migration);
        no_plaintext(&f.0)?;
    }
    Ok(())
}

#[test]
fn wrong_keys_locks_and_abort_never_change_source() -> Result<()> {
    for prepare in [false, true] {
        let f = Fixture::new(2)?;
        let key = DatabaseKey::generate()?;
        let original = fs::read(f.source())?;
        let mut migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
        assert!(NativeMigration::open(f.migration(), owned(&key)).is_err());
        if prepare {
            migration.prepare()?;
        }
        drop(migration);
        let before = bytes(&f.0)?;
        assert!(NativeMigration::open(f.migration(), DatabaseKey::generate()?).is_err());
        assert_eq!(bytes(&f.0)?, before);
        let mut migration = NativeMigration::open(f.migration(), owned(&key))?;
        migration.abort()?;
        migration.abort()?;
        assert_eq!(migration.status()?, MigrationStatus::Aborted);
        assert_eq!(migration.selected_path()?, f.source());
        assert_eq!(fs::read(f.source())?, original);
        assert!(!f.migration().join("encrypted.sqlite").exists());
        assert!(migration.prepare().is_err());
        assert!(migration.activate().is_err());
        assert!(migration.finish().is_err());
    }
    Ok(())
}

#[test]
fn source_changes_and_candidate_changes_prevent_activation_or_cleanup() -> Result<()> {
    for change_candidate in [false, true] {
        let f = Fixture::new(2)?;
        let key = DatabaseKey::generate()?;
        let mut migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
        migration.prepare()?;
        let connection = if change_candidate {
            database_key::open(
                &f.migration().join("encrypted.sqlite"),
                &key,
                OpenPurpose::OpenExisting,
            )?
        } else {
            Connection::open(f.source())?
        };
        connection.execute("INSERT INTO app_settings VALUES('intervening','true')", [])?;
        drop(connection);
        let before = bytes(&f.0)?;
        assert!(migration.activate().is_err());
        assert_eq!(bytes(&f.0)?, before);
        migration.abort()?;
    }
    let f = Fixture::new(2)?;
    let key = DatabaseKey::generate()?;
    let mut migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
    migration.prepare()?;
    migration.activate()?;
    Connection::open(f.source())?
        .execute("INSERT INTO app_settings VALUES('stale-writer','true')", [])?;
    let before = bytes(&f.0)?;
    assert!(migration.finish().is_err());
    assert_eq!(bytes(&f.0)?, before);
    fs::remove_file(f.migration().join("encrypted.sqlite"))?;
    assert!(migration.selected_path().is_err());
    assert!(migration.abort().is_err());
    Ok(())
}

#[test]
fn source_journals_aliases_and_existing_directories_are_refused() -> Result<()> {
    let f = Fixture::new(2)?;
    let key = DatabaseKey::generate()?;
    fs::write(f.0.join("source.db-journal"), b"unresolved-journal")?;
    let before = bytes(&f.0)?;
    assert!(NativeMigration::begin(f.source(), f.migration(), owned(&key)).is_err());
    assert_eq!(bytes(&f.0)?, before);
    fs::remove_file(f.0.join("source.db-journal"))?;
    fs::hard_link(f.source(), f.0.join("alias.db"))?;
    assert!(NativeMigration::begin(f.source(), f.migration(), owned(&key)).is_err());
    fs::remove_file(f.0.join("alias.db"))?;
    std::os::unix::fs::symlink(f.source(), f.0.join("link.db"))?;
    assert!(NativeMigration::begin(f.0.join("link.db"), f.migration(), owned(&key)).is_err());
    fs::create_dir(f.migration())?;
    fs::write(f.migration().join("unrelated"), b"keep")?;
    let before = bytes(&f.0)?;
    assert!(NativeMigration::begin(f.source(), f.migration(), owned(&key)).is_err());
    assert_eq!(bytes(&f.0)?, before);
    Ok(())
}

#[test]
fn partial_copy_is_retryable_and_preserves_source() -> Result<()> {
    let f = Fixture::new(2)?;
    let key = DatabaseKey::generate()?;
    let migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
    fs::write(
        f.migration().join("encrypted.sqlite"),
        b"partial ciphertext",
    )?;
    fs::write(
        f.migration().join("encrypted.sqlite-journal"),
        b"partial ciphertext journal",
    )?;
    let original = fs::read(f.source())?;
    drop(migration);
    let mut migration = NativeMigration::open(f.migration(), owned(&key))?;
    migration.prepare()?;
    assert_eq!(migration.status()?, MigrationStatus::Prepared);
    assert_eq!(fs::read(f.source())?, original);
    migration.abort()?;
    Ok(())
}

#[test]
fn unsupported_schema_fails_without_touching_source() -> Result<()> {
    let f = Fixture::new(2)?;
    Connection::open(f.source())?.execute_batch(
        "CREATE TABLE extra (value TEXT, calculated TEXT GENERATED ALWAYS AS (value) STORED)",
    )?;
    let before = bytes(&f.0)?;
    assert!(NativeMigration::begin(f.source(), f.migration(), DatabaseKey::generate()?).is_err());
    assert_eq!(bytes(&f.0)?, before);
    Ok(())
}

#[test]
fn process_death_recovers_every_publication_boundary() -> Result<()> {
    for stage in [
        "candidate-created",
        "copy-in-progress",
        "copy-committed",
        "before-prepared",
        "prepared",
        "before-active",
        "active",
        "source-unlinked",
        "complete",
    ] {
        let f = Fixture::new(1)?;
        let key = DatabaseKey::generate()?;
        let original = fs::read(f.source())?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "state::encrypted_migration::tests::crash_child",
                "--nocapture",
            ])
            .env("SPP_MIGRATION_TEST_STOP", stage)
            .env("SPP_MIGRATION_TEST_ROOT", &f.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(key.as_ref())?;
        let stdout = child.stdout.take().expect("child stdout");
        let mut observed = false;
        for line in BufReader::new(stdout).lines() {
            if line?.contains(&format!("migration-checkpoint:{stage}")) {
                observed = true;
                break;
            }
        }
        if !observed {
            let output = child.wait_with_output()?;
            anyhow::bail!(
                "migration child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        child.kill()?;
        child.wait()?;
        no_plaintext(&f.migration())?;
        let before = bytes(&f.0)?;
        assert!(NativeMigration::open(f.migration(), DatabaseKey::generate()?).is_err());
        assert_eq!(bytes(&f.0)?, before);
        let mut migration = NativeMigration::open(f.migration(), owned(&key))?;
        if matches!(
            migration.status()?,
            MigrationStatus::Copying | MigrationStatus::Prepared
        ) {
            assert_eq!(migration.selected_path()?, f.source());
            assert_eq!(fs::read(f.source())?, original);
        }
        if migration.status()? == MigrationStatus::Copying {
            migration.prepare()?;
        }
        if migration.status()? == MigrationStatus::Prepared {
            migration.activate()?;
        }
        migration.finish()?;
        let storage = SqliteStorage::connect_encrypted(
            migration.selected_path()?,
            &key,
            OpenPurpose::OpenExisting,
        )?;
        assert_eq!(
            storage.get_setting_json::<String>("protected")?.as_deref(),
            Some(MARKER)
        );
        drop(storage);
        drop(migration);
        no_plaintext(&f.0)?;
    }
    Ok(())
}

fn kill_setup(f: &Fixture, key: &DatabaseKey, stage: &str, recovery: bool) -> Result<()> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "state::encrypted_migration::tests::crash_child",
            "--nocapture",
        ])
        .env("SPP_MIGRATION_TEST_STOP", stage)
        .env("SPP_MIGRATION_TEST_ROOT", &f.0)
        .env(
            "SPP_MIGRATION_TEST_RECOVER",
            if recovery { "1" } else { "0" },
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(key.as_ref())?;
    let mut observed = false;
    for line in BufReader::new(child.stdout.take().expect("child stdout")).lines() {
        if line?.contains(&format!("migration-checkpoint:{stage}")) {
            observed = true;
            break;
        }
    }
    if !observed {
        let output = child.wait_with_output()?;
        anyhow::bail!(
            "setup child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    child.kill()?;
    child.wait()?;
    Ok(())
}

#[test]
fn interrupted_initialization_and_recovery_preserve_source_and_key_policy() -> Result<()> {
    for version in [1, 2] {
        for stage in [
            "setup-directory-created",
            "setup-marker-created",
            "setup-control-created",
            "setup-schema-written",
            "setup-before-commit",
            "setup-committed",
            "setup-retired",
        ] {
            let f = Fixture::new(version)?;
            let key = DatabaseKey::generate()?;
            let original = fs::read(f.source())?;
            kill_setup(&f, &key, stage, false)?;
            let before = bytes(&f.0)?;
            let directories = fs::read_dir(f.migration())?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            assert!(NativeMigration::open(f.migration(), DatabaseKey::generate()?).is_err());
            if stage != "setup-directory-created" {
                assert!(
                    NativeMigration::recover_initialization(
                        f.source(),
                        f.migration(),
                        DatabaseKey::generate()?
                    )
                    .is_err()
                );
                assert_eq!(bytes(&f.0)?, before);
                assert_eq!(
                    fs::read_dir(f.migration())?
                        .map(|e| e.map(|e| e.file_name()))
                        .collect::<std::io::Result<Vec<_>>>()?,
                    directories
                );
            }
            let mut migration = if stage == "setup-retired" {
                assert!(
                    NativeMigration::recover_initialization(f.source(), f.migration(), owned(&key))
                        .is_err()
                );
                NativeMigration::open(f.migration(), owned(&key))?
            } else {
                if stage != "setup-directory-created" {
                    // Recovery itself may die after discarding only incomplete control files.
                    kill_setup(&f, &key, "setup-control-cleared", true)?;
                    let before_retry = bytes(&f.0)?;
                    assert!(
                        NativeMigration::recover_initialization(
                            f.source(),
                            f.migration(),
                            DatabaseKey::generate()?
                        )
                        .is_err()
                    );
                    assert_eq!(bytes(&f.0)?, before_retry);
                }
                NativeMigration::recover_initialization(f.source(), f.migration(), owned(&key))?
            };
            assert_eq!(migration.status()?, MigrationStatus::Copying);
            assert_eq!(fs::read(f.source())?, original);
            assert!(!fs::read_dir(f.migration())?.any(|e| {
                e.expect("read migration directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".setup-")
            }));
            migration.prepare()?;
            migration.activate()?;
            migration.finish()?;
            no_plaintext(&f.0)?;
        }
    }
    Ok(())
}

#[test]
fn setup_recovery_refuses_changed_source_candidates_and_established_state() -> Result<()> {
    for mode in ["source", "candidate", "extra", "symlink"] {
        let f = Fixture::new(2)?;
        let key = DatabaseKey::generate()?;
        kill_setup(&f, &key, "setup-control-created", false)?;
        match mode {
            "source" => {
                Connection::open(f.source())?
                    .execute("INSERT INTO app_settings VALUES('changed','true')", [])?;
            }
            "candidate" => fs::write(f.migration().join("encrypted.sqlite"), b"must remain")?,
            "extra" => fs::write(f.migration().join("other"), b"must remain")?,
            _ => {
                fs::remove_file(f.migration().join("migration.sqlite"))?;
                std::os::unix::fs::symlink(f.source(), f.migration().join("migration.sqlite"))?;
            }
        }
        let before = bytes(&f.0)?;
        assert!(
            NativeMigration::recover_initialization(f.source(), f.migration(), owned(&key))
                .is_err()
        );
        assert_eq!(bytes(&f.0)?, before);
    }
    for state in [
        MigrationStatus::Copying,
        MigrationStatus::Prepared,
        MigrationStatus::Active,
        MigrationStatus::Aborted,
    ] {
        let f = Fixture::new(2)?;
        let key = DatabaseKey::generate()?;
        let mut m = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
        if matches!(state, MigrationStatus::Prepared | MigrationStatus::Active) {
            m.prepare()?;
        }
        if state == MigrationStatus::Active {
            m.activate()?;
        }
        if state == MigrationStatus::Aborted {
            m.abort()?;
        }
        drop(m);
        let before = bytes(&f.0)?;
        assert!(
            NativeMigration::recover_initialization(f.source(), f.migration(), owned(&key))
                .is_err()
        );
        assert_eq!(bytes(&f.0)?, before);
    }
    Ok(())
}

#[test]
fn logical_copy_preserves_typed_rows_triggers_views_and_without_rowid() -> Result<()> {
    let f = Fixture::new(2)?;
    let source = Connection::open(f.source())?;
    source.execute_batch("CREATE TABLE values_test(id INTEGER PRIMARY KEY, n, t, b, f);
        CREATE TABLE keyed_test(k TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
        INSERT INTO values_test VALUES(17,NULL,'text',X'00ff80',1.25);
        INSERT INTO keyed_test VALUES('key','value');
        CREATE VIEW value_view AS SELECT * FROM values_test;
        CREATE TRIGGER audit_values AFTER INSERT ON values_test BEGIN INSERT INTO keyed_test VALUES('trigger','fired'); END;
        CREATE TABLE z_auto(id INTEGER PRIMARY KEY AUTOINCREMENT);
        INSERT INTO z_auto VALUES(10);
        UPDATE sqlite_sequence SET seq=100 WHERE name='z_auto';")?;
    let before = fingerprint(&source)?;
    drop(source);
    let key = DatabaseKey::generate()?;
    let mut migration = NativeMigration::begin(f.source(), f.migration(), owned(&key))?;
    migration.prepare()?;
    migration.activate()?;
    let candidate =
        database_key::open(&migration.selected_path()?, &key, OpenPurpose::OpenExisting)?;
    assert_eq!(fingerprint(&candidate)?, before);
    candidate.execute("INSERT INTO values_test(id) VALUES(18)", [])?;
    assert_eq!(
        candidate.query_row("SELECT value FROM keyed_test WHERE k='trigger'", [], |r| {
            r.get::<_, String>(0)
        })?,
        "fired"
    );
    candidate.execute("INSERT INTO z_auto DEFAULT VALUES", [])?;
    assert_eq!(candidate.last_insert_rowid(), 101);
    Ok(())
}

#[test]
fn full_destination_rolls_back_without_changing_plaintext_source() -> Result<()> {
    let f = Fixture::new(2)?;
    let key = DatabaseKey::generate()?;
    let original = fs::read(f.source())?;
    let mut source =
        Connection::open_with_flags(f.source(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let path = f.0.join("full.db");
    let mut destination = database_key::open(&path, &key, OpenPurpose::CreateNew)?;
    destination.pragma_update(None, "max_page_count", 1)?;
    let error =
        copy_plaintext(&mut source, &mut destination).expect_err("copy must fail when full");
    assert_eq!(
        error
            .downcast_ref::<rusqlite::Error>()
            .and_then(|e| e.sqlite_error_code()),
        Some(rusqlite::ErrorCode::DiskFull)
    );
    assert!(schema(&destination)?.is_empty());
    assert_eq!(fs::read(f.source())?, original);
    Ok(())
}

#[test]
#[ignore = "subprocess helper killed by process_death_recovers_every_publication_boundary"]
fn crash_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("SPP_MIGRATION_TEST_ROOT")?);
    let mut key = DatabaseKey::new([0; 32]);
    std::io::stdin().read_exact(&mut key[..])?;
    let mut migration = if std::env::var("SPP_MIGRATION_TEST_RECOVER").as_deref() == Ok("1") {
        NativeMigration::recover_initialization(
            root.join("source.db"),
            root.join("migration"),
            key,
        )?
    } else {
        NativeMigration::begin(root.join("source.db"), root.join("migration"), key)?
    };
    migration.prepare()?;
    migration.activate()?;
    migration.finish()
}

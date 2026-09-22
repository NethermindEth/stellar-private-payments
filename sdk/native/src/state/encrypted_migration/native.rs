use super::{check_integrity, copy_plaintext, fingerprint, initialization_marker};
use crate::state::database_key::{self, DatabaseKey, OpenPurpose};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

const CONTROL: &str = "migration.sqlite";
const CANDIDATE: &str = "encrypted.sqlite";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    /// Source is authoritative. An interrupted candidate can be rebuilt by
    /// prepare.
    Copying,
    /// Candidate validated; source remains authoritative until explicit
    /// activation.
    Prepared,
    /// Encrypted database is authoritative, even if the plaintext source
    /// remains.
    Active,
    /// Encrypted database is authoritative and the original source has been
    /// unlinked.
    Complete,
    /// Migration was cancelled before activation; source remains authoritative.
    Aborted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    status: MigrationStatus,
    source: PathBuf,
    source_device: u64,
    source_inode: u64,
    source_hash: String,
    candidate_hash: Option<String>,
}

/// An explicit, owner-serialized migration. Stop all source readers/writers
/// before begin, keep them stopped through activation, and route subsequent
/// opens through selected_path. The directory lock serializes coordinators, not
/// arbitrary SQLite clients. Never open the stale plaintext path after
/// activation.
///
/// Use a NEW private directory. A small encrypted control database records
/// state; the candidate is always encrypted. Retain a recoverable wrapped key
/// before begin. Open after a crash, then inspect status: prepare can retry
/// Copying, activate can retry Prepared, and finish can retry Active. Invalid
/// state fails closed. Opening can retire a setup marker after authenticating
/// durable state; it never removes a database or converts application data.
///
/// Aborting is supported before activation. After activation, keep the
/// encrypted database: returning to the old source could silently lose
/// committed writes. finish unlinks the source; it cannot securely erase
/// filesystem snapshots, SSD blocks or external backups. Those are outside the
/// database migration boundary.
pub struct NativeMigration {
    directory: PathBuf,
    control: Connection,
    key: DatabaseKey,
    // Release ownership only after the SQLite connection has closed.
    _lock: DirectoryLock,
}

struct DirectoryLock(File);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // Explicit unlock also releases an inherited open-file-description lock
        // during another thread's fork/exec window; closing our descriptor
        // alone can keep the lock alive until the child closes its
        // duplicate.
        let _ = self.0.unlock();
    }
}

impl NativeMigration {
    /// Start a migration record without copying or changing the source
    /// database. The supplied directory must not exist. After an
    /// interrupted setup, use recover_initialization with the same source
    /// and key; ordinary open still requires a valid control record.
    pub fn begin(
        source: impl AsRef<Path>,
        directory: impl AsRef<Path>,
        key: DatabaseKey,
    ) -> Result<Self> {
        let (record, _source_lock) = initial_record(source.as_ref())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory.as_ref())?;
        let directory = directory.as_ref().canonicalize()?;
        sync_directory(
            directory
                .parent()
                .context("migration directory has no parent")?,
        )?;
        let lock = lock_directory(&directory)?;
        checkpoint("setup-directory-created");
        publish_marker(&directory, &key, &record)?;
        Self::initialize(directory, lock, key, record)
    }

    /// Explicitly retry an interrupted begin. Requires the original unchanged
    /// source and key, the authenticated setup marker, and no candidate files.
    /// An entirely empty directory predates key binding and can also be
    /// initialized. Refuses legacy unmarked control files and every
    /// established migration.
    pub fn recover_initialization(
        source: impl AsRef<Path>,
        directory: impl AsRef<Path>,
        key: DatabaseKey,
    ) -> Result<Self> {
        let (record, _source_lock) = initial_record(source.as_ref())?;
        ensure!(
            !fs::symlink_metadata(directory.as_ref())?
                .file_type()
                .is_symlink(),
            "migration directory is a symlink"
        );
        let directory = directory.as_ref().canonicalize()?;
        let lock = lock_directory(&directory)?;
        let marker = marker_name(&key, &record)?;
        let names = fs::read_dir(&directory)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        if names.is_empty() {
            publish_marker(&directory, &key, &record)?;
        } else {
            ensure!(
                names.iter().any(|n| n == marker.as_str()),
                "initialization key or source does not match, or setup already completed"
            );
            marker_directory(&directory.join(&marker))?;
            for name in names {
                ensure!(
                    name == marker.as_str()
                        || [
                            CONTROL.to_string(),
                            format!("{CONTROL}-journal"),
                            format!("{CONTROL}-wal"),
                            format!("{CONTROL}-shm")
                        ]
                        .iter()
                        .any(|n| name == n.as_str()),
                    "unexpected files or candidate in migration directory"
                );
            }
        }
        // The marker cannot survive a successful begin/open, so no candidate
        // or application writes can belong to these incomplete control files.
        let mut owned_files = Vec::new();
        for path in
            sidecars(&directory.join(CONTROL)).chain(std::iter::once(directory.join(CONTROL)))
        {
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    regular_file(&path)?;
                    owned_files.push(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // Validate the entire set before the first removal (including
        // symlinks).
        for path in owned_files {
            fs::remove_file(path)?;
        }
        sync_directory(&directory)?;
        checkpoint("setup-control-cleared");
        Self::initialize(directory, lock, key, record)
    }

    fn initialize(
        directory: PathBuf,
        lock: DirectoryLock,
        key: DatabaseKey,
        record: Record,
    ) -> Result<Self> {
        let mut control =
            database_key::open(&directory.join(CONTROL), &key, OpenPurpose::CreateNew)?;
        checkpoint("setup-control-created");
        control.pragma_update(None, "synchronous", "FULL")?;
        let tx = control.transaction()?;
        tx.execute_batch("CREATE TABLE migration_state (id INTEGER PRIMARY KEY CHECK(id=1), record TEXT NOT NULL)")?;
        checkpoint("setup-schema-written");
        tx.execute(
            "INSERT INTO migration_state VALUES(1,?1)",
            [serde_json::to_string(&record)?],
        )?;
        checkpoint("setup-before-commit");
        tx.commit()?;
        sync_directory(&directory)?;
        checkpoint("setup-committed");
        retire_marker(&directory, &key, &record)?;
        checkpoint("setup-retired");
        Ok(Self {
            directory,
            _lock: lock,
            control,
            key,
        })
    }

    /// Reopen existing state. Wrong keys fail before journal recovery or
    /// writes.
    pub fn open(directory: impl AsRef<Path>, key: DatabaseKey) -> Result<Self> {
        ensure!(
            !fs::symlink_metadata(directory.as_ref())?
                .file_type()
                .is_symlink(),
            "migration directory is a symlink"
        );
        let directory = directory.as_ref().canonicalize()?;
        let lock = lock_directory(&directory)?;
        regular_file(&directory.join(CONTROL))?;
        let control =
            database_key::open(&directory.join(CONTROL), &key, OpenPurpose::OpenExisting)?;
        control.pragma_update(None, "synchronous", "FULL")?;
        let migration = Self {
            directory,
            _lock: lock,
            control,
            key,
        };
        let record = migration.record()?;
        retire_marker(&migration.directory, &migration.key, &record)?;
        Ok(migration)
    }

    pub fn status(&self) -> Result<MigrationStatus> {
        Ok(self.record()?.status)
    }

    /// Return only the authoritative path. There is no fallback to plaintext if
    /// the active encrypted database is absent, corrupt or fails
    /// authentication.
    pub fn selected_path(&self) -> Result<PathBuf> {
        let record = self.record()?;
        if matches!(
            record.status,
            MigrationStatus::Active | MigrationStatus::Complete
        ) {
            let path = self.candidate();
            regular_file(&path)?;
            database_key::validate_read_only(&path, Some(&self.key))?;
            Ok(path)
        } else {
            regular_file(&record.source)?;
            Ok(record.source)
        }
    }

    /// Copy/retry from the original snapshot, validate, apply the SDK
    /// migrations, close/reopen and validate again, then durably publish
    /// Prepared.
    pub fn prepare(&mut self) -> Result<()> {
        let mut record = self.record()?;
        ensure!(
            record.status == MigrationStatus::Copying,
            "migration is not awaiting a copy"
        );
        let mut source = open_source(&record.source)?;
        verify_source(&record)?;
        self.remove_candidate()?;
        let mut candidate =
            database_key::open(&self.candidate(), &self.key, OpenPurpose::CreateNew)?;
        checkpoint("candidate-created");
        candidate.pragma_update(None, "synchronous", "FULL")?;
        copy_plaintext(&mut source, &mut candidate)?;
        checkpoint("copy-committed");
        let expected = fingerprint(&candidate)?;
        drop(candidate);
        verify_source(&record)?;
        let reopened = self.open_candidate()?;
        ensure!(
            fingerprint(&reopened)? == expected,
            "candidate changed on reopen"
        );
        drop(reopened);
        File::open(self.candidate())?.sync_all()?;
        sync_directory(&self.directory)?;
        record.candidate_hash = Some(expected);
        record.status = MigrationStatus::Prepared;
        checkpoint("before-prepared");
        self.save(&record)?;
        checkpoint("prepared");
        Ok(())
    }

    /// Atomically select the validated encrypted candidate. Callers must switch
    /// their storage path using selected_path; ordinary SDK opens are
    /// unchanged.
    pub fn activate(&mut self) -> Result<()> {
        let mut record = self.record()?;
        ensure!(
            record.status == MigrationStatus::Prepared,
            "migration is not prepared"
        );
        let source = open_source(&record.source)?;
        source.execute_batch("BEGIN")?;
        // Hold a SQLite read lock through publication, in addition to the
        // caller's obligation to stop writers for the entire migration.
        let _: i64 = source.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        verify_source(&record)?;
        let candidate = self.open_candidate()?;
        ensure!(
            Some(fingerprint(&candidate)?) == record.candidate_hash,
            "candidate changed before activation"
        );
        drop(candidate);
        File::open(self.candidate())?.sync_all()?;
        sync_directory(&self.directory)?;
        record.status = MigrationStatus::Active;
        checkpoint("before-active");
        self.save(&record)?;
        checkpoint("active");
        Ok(())
    }

    /// Cancel before activation. The source is untouched. Repeating abort after
    /// a crash completes deletion of this coordinator's incomplete candidate.
    pub fn abort(&mut self) -> Result<()> {
        let mut record = self.record()?;
        ensure!(
            matches!(
                record.status,
                MigrationStatus::Copying | MigrationStatus::Prepared | MigrationStatus::Aborted
            ),
            "cannot roll back to plaintext after activation"
        );
        record.status = MigrationStatus::Aborted;
        self.save(&record)?;
        self.remove_candidate()
    }

    /// Explicitly remove the unchanged original only AFTER encrypted
    /// activation. Refuses source replacement/modification or outstanding
    /// journals. Retrying after a crash between unlink and the final state
    /// commit is safe.
    pub fn finish(&mut self) -> Result<()> {
        let mut record = self.record()?;
        ensure!(
            matches!(
                record.status,
                MigrationStatus::Active | MigrationStatus::Complete
            ),
            "migration is not active"
        );
        let candidate = self.open_candidate()?;
        check_integrity(&candidate)?;
        drop(candidate);
        if record.status == MigrationStatus::Complete {
            return Ok(());
        }
        no_sidecars(&record.source)?;
        if record.source.try_exists()? {
            verify_source(&record)?;
            fs::remove_file(&record.source)?;
        }
        sync_directory(record.source.parent().context("source has no parent")?)?;
        checkpoint("source-unlinked");
        record.status = MigrationStatus::Complete;
        self.save(&record)?;
        checkpoint("complete");
        Ok(())
    }

    fn candidate(&self) -> PathBuf {
        self.directory.join(CANDIDATE)
    }

    fn open_candidate(&self) -> Result<Connection> {
        regular_file(&self.candidate())?;
        database_key::open(&self.candidate(), &self.key, OpenPurpose::OpenExisting)
    }

    fn record(&self) -> Result<Record> {
        let json: String =
            self.control
                .query_row("SELECT record FROM migration_state WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        let record: Record = serde_json::from_str(&json)?;
        ensure!(
            record.version == 1 && record.source.is_absolute(),
            "unsupported migration state"
        );
        ensure!(
            record.source != self.candidate() && record.source != self.directory.join(CONTROL),
            "invalid migration source"
        );
        Ok(record)
    }

    fn save(&mut self, record: &Record) -> Result<()> {
        ensure!(
            self.control.execute(
                "UPDATE migration_state SET record=?1 WHERE id=1",
                [serde_json::to_string(record)?]
            )? == 1,
            "missing migration state"
        );
        sync_directory(&self.directory)
    }

    fn remove_candidate(&self) -> Result<()> {
        // Only fixed files inside the new private migration directory are owned
        // by this operation. Never recursively remove directories or source
        // files.
        for path in std::iter::once(self.candidate()).chain(sidecars(&self.candidate())) {
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    regular_file(&path)?;
                    fs::remove_file(path)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        sync_directory(&self.directory)
    }
}

fn initial_record(source: &Path) -> Result<(Record, Connection)> {
    regular_file(source)?;
    let source = source.canonicalize()?;
    let connection = open_source(&source)?;
    connection.execute_batch("BEGIN")?;
    fingerprint(&connection)?;
    let metadata = regular_file(&source)?;
    let source_hash = file_hash(&source)?;
    Ok((
        Record {
            version: 1,
            status: MigrationStatus::Copying,
            source,
            source_device: metadata.dev(),
            source_inode: metadata.ino(),
            source_hash,
            candidate_hash: None,
        },
        connection,
    ))
}

fn marker_name(key: &DatabaseKey, record: &Record) -> Result<String> {
    Ok(initialization_marker(
        key,
        "native",
        &serde_json::to_vec(&(
            &record.source,
            record.source_device,
            record.source_inode,
            &record.source_hash,
        ))?,
    ))
}

fn marker_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && fs::read_dir(path)?.next().is_none(),
        "invalid initialization marker"
    );
    Ok(())
}

fn publish_marker(directory: &Path, key: &DatabaseKey, record: &Record) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory.join(marker_name(key, record)?))?;
    sync_directory(directory)?;
    checkpoint("setup-marker-created");
    Ok(())
}

fn retire_marker(directory: &Path, key: &DatabaseKey, record: &Record) -> Result<()> {
    let marker = directory.join(marker_name(key, record)?);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            ensure!(
                record.status == MigrationStatus::Copying,
                "unexpected setup marker"
            );
            marker_directory(&marker)?;
            fs::remove_dir(marker)?;
            sync_directory(directory)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn lock_directory(directory: &Path) -> Result<DirectoryLock> {
    let file = File::open(directory)?;
    file.try_lock()
        .context("migration coordinator is already open")?;
    Ok(DirectoryLock(file))
}

#[test]
fn explicit_unlock_releases_a_duplicated_description() -> Result<()> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)?;
    let directory = std::env::temp_dir().join(format!("spp-lock-{}", hex::encode(random)));
    fs::create_dir(&directory)?;
    let result = (|| -> Result<()> {
        let lock = lock_directory(&directory)?;
        // dup and fork share the same open file description on Linux.
        let inherited = lock.0.try_clone()?;
        assert!(lock_directory(&directory).is_err());
        drop(lock);
        let next = lock_directory(&directory)?;
        drop(inherited);
        drop(next);
        Ok(())
    })();
    fs::remove_dir(directory)?;
    result
}

fn sync_directory(directory: &Path) -> Result<()> {
    Ok(File::open(directory)?.sync_all()?)
}

fn regular_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
        "migration requires a regular file with one link"
    );
    Ok(metadata)
}

fn sidecars(path: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    ["-journal", "-wal", "-shm"].into_iter().map(|suffix| {
        let mut value = path.as_os_str().to_owned();
        value.push(suffix);
        PathBuf::from(value)
    })
}

fn no_sidecars(path: &Path) -> Result<()> {
    for sidecar in sidecars(path) {
        match fs::symlink_metadata(sidecar) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!("close and recover source database journals before migration"),
        }
    }
    Ok(())
}

fn open_source(path: &Path) -> Result<Connection> {
    regular_file(path)?;
    no_sidecars(path)?;
    database_key::validate_read_only(path, None)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(connection)
}

fn file_hash(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
    loop {
        let count = input.read(&mut buffer[..])?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn verify_source(record: &Record) -> Result<()> {
    no_sidecars(&record.source)?;
    let metadata = regular_file(&record.source)?;
    ensure!(
        metadata.dev() == record.source_device
            && metadata.ino() == record.source_inode
            && file_hash(&record.source)? == record.source_hash,
        "source changed since migration began"
    );
    Ok(())
}

#[cfg(not(test))]
fn checkpoint(_: &str) {}

#[cfg(test)]
pub(super) fn checkpoint(name: &str) {
    if std::env::var("SPP_MIGRATION_TEST_STOP").ok().as_deref() == Some(name) {
        use std::io::Write;
        println!("migration-checkpoint:{name}");
        std::io::stdout().flush().expect("test checkpoint output");
        loop {
            std::thread::park();
        }
    }
}

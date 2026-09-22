//! Own both OPFS pools until the explicit migration handle closes. No plaintext
//! intermediate is persisted: rows move directly between SQLite connections.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlite_wasm_vfs::sahpool::{OpfsSAHPoolCfg, OpfsSAHPoolUtil, install};
use std::path::Path;
use stellar_private_payments::state::{
    database_key::{self, DatabaseKey, OpenPurpose},
    encrypted_migration::{copy_plaintext, fingerprint, initialization_marker},
};

use crate::protocol::MigrationAction;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{FileSystemDirectoryHandle, FileSystemGetDirectoryOptions, WorkerGlobalScope};

const SOURCE: &str = "spp.db";
const CANDIDATE: &str = "spp.encrypted.db";
const CONTROL: &str = "spp.migration.db";
const SOURCE_VFS: &str = "opfs-migration-source";
const TARGET_VFS: &str = "opfs-migration-target";

/// Ordinary storage must not expose a prepared copy when application metadata
/// is lost. The encrypted control record is authoritative for activation.
pub(super) fn check_open(util: &OpfsSAHPoolUtil, key: &DatabaseKey, creating: bool) -> Result<()> {
    if !util.exists(CONTROL)? {
        return Ok(());
    }
    ensure!(!creating, "migration owns database creation");
    let control = database_key::open(Path::new(CONTROL), key, OpenPurpose::OpenExisting)?;
    let value: String =
        control.query_row("SELECT record FROM migration_state WHERE id=1", [], |r| {
            r.get(0)
        })?;
    let record: Record = serde_json::from_str(&value)?;
    ensure!(
        record.version == 1 && record.source_hash.len() == 32,
        "unsupported migration state"
    );
    ensure!(
        matches!(
            record.phase,
            Phase::Active | Phase::Cleaning | Phase::Complete
        ),
        "migration requires explicit activation before encrypted storage can open"
    );
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Copying,
    Prepared,
    Active,
    Cleaning,
    Complete,
    Aborted,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Copying => "copying",
            Self::Prepared => "prepared",
            Self::Active => "active",
            Self::Cleaning => "cleaning",
            Self::Complete => "complete",
            Self::Aborted => "aborted",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    phase: Phase,
    source_hash: Vec<u8>,
    candidate_hash: Option<String>,
}

struct Pool {
    util: OpfsSAHPoolUtil,
    codec: bool,
}
impl Pool {
    async fn acquire(name: &str, directory: &str) -> Result<Self> {
        let cfg = OpfsSAHPoolCfg {
            vfs_name: name.into(),
            directory: directory.into(),
            ..Default::default()
        };
        let mut attempts = 0u32;
        loop {
            match install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, false).await {
                Ok(util) => return Ok(Self { util, codec: false }),
                Err(e) if super::storage::is_opfs_locked_error(&e) && attempts < 10 => {
                    attempts = attempts.saturating_add(1);
                    gloo_timers::future::TimeoutFuture::new(200).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[allow(unsafe_code)]
    fn add_codec(&mut self) -> Result<()> {
        // SAFETY: this pool has been registered in this worker. Its connections
        // are closed before Drop removes the codec and releases the pool.
        ensure!(
            unsafe { sqlite_wasm_rs::sqlite3mc_vfs_create(c"opfs-migration-target".as_ptr(), 1) }
                == sqlite_wasm_rs::SQLITE_OK,
            "failed to register migration codec"
        );
        self.codec = true;
        Ok(())
    }
}
impl Drop for Pool {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.codec {
            // SAFETY: BrowserMigration drops its control connection before the
            // pools; all other connections are local to completed operations.
            unsafe {
                sqlite_wasm_rs::sqlite3mc_vfs_destroy(
                    c"multipleciphers-opfs-migration-target".as_ptr(),
                );
            }
        }
        let _ = self.util.pause_vfs();
    }
}

pub(super) struct BrowserMigration {
    // Field order keeps the SQLite handle closed before either VFS is released.
    control: Connection,
    source: Pool,
    target: Pool,
    key: DatabaseKey,
}

impl BrowserMigration {
    pub(super) async fn open(
        key: DatabaseKey,
        create_new: bool,
        recover_setup: bool,
    ) -> Result<Self> {
        let source = Pool::acquire(SOURCE_VFS, ".opfs-sahpool").await?;
        let mut target = Pool::acquire(TARGET_VFS, ".opfs-sahpool-encrypted").await?;
        ensure!(
            !(create_new && recover_setup),
            "conflicting initialization policies"
        );
        let setup = SetupDirectory::open().await?;
        let markers = setup.markers().await?;
        let initializing = create_new || recover_setup;
        if !initializing {
            ensure!(target.util.exists(CONTROL)?, "migration control is missing");
        }
        // Validate before publishing the source-bound marker or changing
        // control files.
        let initial = if initializing {
            ensure!(
                target.util.list().iter().all(|name| name == CONTROL
                    || ["-journal", "-wal", "-shm"]
                        .iter()
                        .any(|suffix| name == &format!("{CONTROL}{suffix}"))),
                "encrypted candidate or unexpected files already exist"
            );
            let connection = open_source(&source.util)?;
            fingerprint(&connection)?;
            let record = Record {
                version: 1,
                phase: Phase::Copying,
                source_hash: source_hash(&source.util)?,
                candidate_hash: None,
            };
            let marker = setup_marker(&key, &record);
            if create_new {
                ensure!(
                    target.util.list().is_empty() && markers.is_empty(),
                    "migration setup already exists; resume or explicitly recover it"
                );
                setup.publish(&marker).await?;
            } else if markers.is_empty() && target.util.list().is_empty() {
                // No authenticated state or database was created yet.
                setup.publish(&marker).await?;
            } else {
                ensure!(
                    markers == [marker.clone()],
                    "initialization key or source does not match, or setup already completed"
                );
                setup.validate(&marker).await?;
            }
            if recover_setup {
                for name in [
                    format!("{CONTROL}-journal"),
                    format!("{CONTROL}-wal"),
                    format!("{CONTROL}-shm"),
                    CONTROL.into(),
                ] {
                    target.util.delete_db(&name)?;
                }
            }
            Some(record)
        } else {
            None
        };
        target.add_codec()?;
        let mut control = database_key::open(
            Path::new(CONTROL),
            &key,
            if initializing {
                OpenPurpose::CreateNew
            } else {
                OpenPurpose::OpenExisting
            },
        )?;
        control.pragma_update(None, "synchronous", "FULL")?;
        if let Some(record) = initial {
            let tx = control.transaction()?;
            tx.execute_batch("CREATE TABLE migration_state(id INTEGER PRIMARY KEY CHECK(id=1), record TEXT NOT NULL)")?;
            tx.execute(
                "INSERT INTO migration_state VALUES(1,?1)",
                [serde_json::to_string(&record)?],
            )?;
            tx.commit()?;
        }
        let migration = Self {
            control,
            source,
            target,
            key,
        };
        let record = migration.record()?;
        let marker = setup_marker(&migration.key, &record);
        let markers = setup.markers().await?;
        if !markers.is_empty() {
            ensure!(
                record.phase == Phase::Copying && markers == [marker.clone()],
                "unexpected initialization marker"
            );
            setup.retire(&marker).await?;
        }
        // No candidate-producing operation is exposed until retirement
        // completes.
        Ok(migration)
    }

    pub(super) fn action(&mut self, action: MigrationAction) -> Result<String> {
        let mut record = self.record()?;
        match action {
            MigrationAction::Status => {}
            MigrationAction::Prepare => {
                ensure!(
                    record.phase == Phase::Copying,
                    "migration is not awaiting a copy"
                );
                self.verify_source(&record)?;
                let mut source = open_source(&self.source.util)?;
                self.remove_candidate()?;
                let mut candidate =
                    database_key::open(Path::new(CANDIDATE), &self.key, OpenPurpose::CreateNew)?;
                candidate.pragma_update(None, "synchronous", "FULL")?;
                copy_plaintext(&mut source, &mut candidate)?;
                let expected = fingerprint(&candidate)?;
                drop(candidate);
                self.verify_source(&record)?;
                let reopened = self.candidate()?;
                ensure!(
                    fingerprint(&reopened)? == expected,
                    "candidate changed on reopen"
                );
                drop(reopened);
                record.candidate_hash = Some(expected);
                record.phase = Phase::Prepared;
                self.save(&record)?;
            }
            MigrationAction::Activate => {
                ensure!(record.phase == Phase::Prepared, "migration is not prepared");
                self.verify_source(&record)?;
                let candidate = self.candidate()?;
                ensure!(
                    Some(fingerprint(&candidate)?) == record.candidate_hash,
                    "candidate changed before activation"
                );
                drop(candidate);
                record.phase = Phase::Active;
                self.save(&record)?;
            }
            MigrationAction::Abort => {
                ensure!(
                    matches!(
                        record.phase,
                        Phase::Copying | Phase::Prepared | Phase::Aborted
                    ),
                    "cannot roll back to plaintext after activation"
                );
                record.phase = Phase::Aborted;
                self.save(&record)?;
                self.remove_candidate()?;
            }
            MigrationAction::Restart => {
                ensure!(
                    record.phase == Phase::Aborted,
                    "only an aborted migration can restart"
                );
                let source = open_source(&self.source.util)?;
                fingerprint(&source)?;
                self.remove_candidate()?;
                record.source_hash = source_hash(&self.source.util)?;
                record.candidate_hash = None;
                record.phase = Phase::Copying;
                self.save(&record)?;
            }
            MigrationAction::Finish => {
                ensure!(
                    matches!(
                        record.phase,
                        Phase::Active | Phase::Cleaning | Phase::Complete
                    ),
                    "migration is not active"
                );
                let candidate = self.candidate()?;
                fingerprint(&candidate)?;
                drop(candidate);
                if record.phase == Phase::Active {
                    no_journals(&self.source.util, SOURCE)?;
                    if self.source.util.exists(SOURCE)? {
                        self.verify_source(&record)?;
                    }
                    record.phase = Phase::Cleaning;
                    self.save(&record)?;
                }
                if record.phase == Phase::Cleaning {
                    no_journals(&self.source.util, SOURCE)?;
                    if self.source.util.exists(SOURCE)? {
                        // A terminated delete can leave a mapped, empty file.
                        // Any remaining full source must still match the copy.
                        let mut bytes = self.source.util.export_db(SOURCE)?;
                        let empty = bytes.is_empty();
                        database_key::clear_transport(&mut bytes);
                        if !empty {
                            self.verify_source(&record)?;
                        }
                        self.source.util.delete_db(SOURCE)?;
                    }
                    record.phase = Phase::Complete;
                    self.save(&record)?;
                }
            }
        }
        // Active/complete state never falls back to the plaintext source.
        if matches!(
            record.phase,
            Phase::Active | Phase::Cleaning | Phase::Complete
        ) {
            drop(self.candidate()?);
        }
        Ok(record.phase.name().into())
    }

    fn candidate(&self) -> Result<Connection> {
        ensure!(
            self.target.util.exists(CANDIDATE)?,
            "encrypted candidate is missing"
        );
        database_key::open(Path::new(CANDIDATE), &self.key, OpenPurpose::OpenExisting)
    }

    fn record(&self) -> Result<Record> {
        let value: String =
            self.control
                .query_row("SELECT record FROM migration_state WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        let record: Record = serde_json::from_str(&value)?;
        ensure!(
            record.version == 1 && record.source_hash.len() == 32,
            "unsupported migration state"
        );
        Ok(record)
    }

    fn save(&self, record: &Record) -> Result<()> {
        ensure!(
            self.control.execute(
                "UPDATE migration_state SET record=?1 WHERE id=1",
                [serde_json::to_string(record)?]
            )? == 1,
            "missing migration state"
        );
        Ok(())
    }

    fn verify_source(&self, record: &Record) -> Result<()> {
        no_journals(&self.source.util, SOURCE)?;
        ensure!(
            source_hash(&self.source.util)? == record.source_hash,
            "plaintext source changed since migration began"
        );
        Ok(())
    }

    fn remove_candidate(&self) -> Result<()> {
        for name in [
            CANDIDATE.to_string(),
            format!("{CANDIDATE}-journal"),
            format!("{CANDIDATE}-wal"),
            format!("{CANDIDATE}-shm"),
        ] {
            self.target.util.delete_db(&name)?;
        }
        Ok(())
    }
}

fn no_journals(pool: &OpfsSAHPoolUtil, name: &str) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        ensure!(
            !pool.exists(&format!("{name}{suffix}"))?,
            "close and recover the source database before migration"
        );
    }
    Ok(())
}

fn open_source(pool: &OpfsSAHPoolUtil) -> Result<Connection> {
    ensure!(pool.exists(SOURCE)?, "plaintext source is missing");
    no_journals(pool, SOURCE)?;
    Ok(Connection::open_with_flags_and_vfs(
        SOURCE,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        SOURCE_VFS,
    )?)
}

fn source_hash(pool: &OpfsSAHPoolUtil) -> Result<Vec<u8>> {
    let mut bytes = pool.export_db(SOURCE)?;
    let hash = Sha256::digest(&bytes).to_vec();
    database_key::clear_transport(&mut bytes);
    Ok(hash)
}

fn setup_marker(key: &DatabaseKey, record: &Record) -> String {
    initialization_marker(key, "opfs", &record.source_hash)
}

// Directory entry creation is one OPFS operation: unlike a SQLite page or SAH
// mapping header, it cannot leave a partially written authentication token.
// Both pools remain exclusively held throughout marker publication/retirement.
struct SetupDirectory(FileSystemDirectoryHandle);
impl SetupDirectory {
    async fn open() -> Result<Self> {
        let scope = js_sys::global()
            .dyn_into::<WorkerGlobalScope>()
            .map_err(|e| setup_error(e.into()))?;
        let root: FileSystemDirectoryHandle =
            JsFuture::from(scope.navigator().storage().get_directory())
                .await
                .map_err(setup_error)?
                .into();
        Ok(Self(
            JsFuture::from(root.get_directory_handle(".opfs-sahpool-encrypted"))
                .await
                .map_err(setup_error)?
                .into(),
        ))
    }

    async fn markers(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let iter = self.0.entries();
        loop {
            let item: js_sys::IteratorNext = JsFuture::from(iter.next().map_err(setup_error)?)
                .await
                .map_err(setup_error)?
                .into();
            if item.done() {
                break;
            }
            let entry: js_sys::Array = item.value().into();
            let name = entry
                .get(0)
                .as_string()
                .ok_or_else(|| anyhow::anyhow!("invalid directory entry"))?;
            if name.starts_with(".setup-") {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    async fn publish(&self, name: &str) -> Result<()> {
        let options = FileSystemGetDirectoryOptions::new();
        options.set_create(true);
        JsFuture::from(self.0.get_directory_handle_with_options(name, &options))
            .await
            .map_err(setup_error)?;
        Ok(())
    }

    async fn validate(&self, name: &str) -> Result<()> {
        let marker: FileSystemDirectoryHandle = JsFuture::from(self.0.get_directory_handle(name))
            .await
            .map_err(setup_error)?
            .into();
        let item: js_sys::IteratorNext =
            JsFuture::from(marker.entries().next().map_err(setup_error)?)
                .await
                .map_err(setup_error)?
                .into();
        ensure!(item.done(), "initialization marker is not empty");
        Ok(())
    }

    async fn retire(&self, name: &str) -> Result<()> {
        self.validate(name).await?;
        JsFuture::from(self.0.remove_entry(name))
            .await
            .map_err(setup_error)?;
        Ok(())
    }
}
fn setup_error(_: JsValue) -> anyhow::Error {
    anyhow::anyhow!("migration initialization directory operation failed")
}

use crate::protocol::{
    AdminASPRequest, AspSecret, CorrelatedRequest, DisclaimerStatePayload, DisclosureInputs,
    DisclosureInputsRequest, PublicEncryptionKeyPair, PublicNoteKeyPair, StorageWorkerRequest,
    StorageWorkerResponse, UserKeys,
};
use anyhow::{Result, anyhow};
use futures::{FutureExt, channel::mpsc, stream::StreamExt};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use std::cell::RefCell;
use stellar_private_payments::{
    Error, Storage,
    chain::ContractDataStorage,
    disclosure::{BuildDisclosureInputs, build_disclosure_inputs},
    planner::SpendableNote,
    state::{SqliteStorage, StoredUserKeys, process_local_state_batch},
    transact::{BuildTransactParams, TransactRequest, build_transact_params},
    types::{
        ContractConfig, ContractsEventData, EncryptionPublicKey, Field, NotePublicKey,
        OperationalFeedItem, PortfolioBalance, PortfolioPoolEntry, RecipientLookup, Sensitive,
        SyncMetadata, UserNoteSummary,
    },
    zk::{
        crypto::asp_membership_leaf,
        encryption::{derive_encryption_and_note_keypairs, derive_membership_blinding},
        flows::TransactParams,
    },
};
use tracing::Instrument;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use wasm_bindgen::JsError;
use wasm_bindgen_futures::spawn_local;

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

#[derive(Clone, Debug)]
enum InitState {
    #[cfg(feature = "sqlite3mc")]
    Locked,
    Pending,
    Ready,
    Failed(String),
}

#[cfg(feature = "sqlite3mc")]
enum OpenRequest {
    Plaintext,
    Encrypted {
        key: stellar_private_payments::state::database_key::DatabaseKey,
        purpose: stellar_private_payments::state::database_key::OpenPurpose,
    },
}

const fn initial_state() -> InitState {
    #[cfg(feature = "sqlite3mc")]
    {
        InitState::Locked
    }
    #[cfg(not(feature = "sqlite3mc"))]
    {
        InitState::Pending
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn is_opfs_locked_error(err: &sqlite_wasm_vfs::sahpool::OpfsSAHError) -> bool {
    // `OpfsSAHError`'s `Display`/`Debug` impls use fixed messages and do not
    // interpolate the wrapped `JsValue`, so the real DOMException (thrown by
    // the browser when another tab/worker still holds the OPFS sync access
    // handles) must be inspected directly rather than via `to_string()`.
    let sqlite_wasm_vfs::sahpool::OpfsSAHError::CreateSyncAccessHandle(js_err) = err else {
        return false;
    };
    js_err
        .dyn_ref::<web_sys::DomException>()
        .is_some_and(|e| e.name() == "NoModificationAllowedError")
}

thread_local! {
    static STORAGE: RefCell<Option<SqliteStorage>> = const { RefCell::new(None) };
    static PROCESSOR_TX: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(initial_state()) };
    #[cfg(target_arch = "wasm32")]
    static SAH_POOL: RefCell<Option<sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil>> = const { RefCell::new(None) };
    #[cfg(all(target_arch = "wasm32", feature = "sqlite3mc"))]
    static MIGRATION: RefCell<Option<super::storage_migration::BrowserMigration>> = const { RefCell::new(None) };
}

macro_rules! with_storage {
    ($storage:ident => $body:expr) => {
        STORAGE.with(|s| {
            let borrow = s.borrow();
            // We must return the Result from the closure
            let $storage = borrow
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;

            // This ensures the body expression's Result is returned by the closure
            Ok::<_, anyhow::Error>($body)
        })
    };
}

macro_rules! with_storage_mut {
    ($storage:ident => $body:expr) => {
        STORAGE.with(|s| {
            let mut borrow = s.borrow_mut();
            let $storage = borrow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;

            Ok::<_, anyhow::Error>($body)
        })
    };
}

pub fn worker_main() {
    let worker_span = tracing::info_span!("worker", worker = WORKER_NAME);
    {
        let _guard = worker_span.enter();
        crate::telemetry::init_telemetry(None);
        crate::telemetry::install_panic_hook();
        tracing::debug!("[{WORKER_NAME}] starting...");
    }
    StorageWorker::registrar().register();
    #[cfg(not(feature = "sqlite3mc"))]
    spawn_local(
        async move {
            if let Err(e) = init().await {
                tracing::error!("[{WORKER_NAME}] init failed: {e:?}");
            }
        }
        .instrument(worker_span),
    );
}

// A prior page's worker still releases its OPFS sync access handles
// asynchronously after termination, so a fresh worker started right after a
// navigation can transiently race that teardown. Retry for a bit before
// treating the lock as held by a genuinely separate tab/window.
#[cfg(target_arch = "wasm32")]
const OPFS_LOCK_RETRY_ATTEMPTS: u32 = 10;
#[cfg(target_arch = "wasm32")]
const OPFS_LOCK_RETRY_DELAY_MS: u32 = 200;

async fn init(#[cfg(feature = "sqlite3mc")] opening: OpenRequest) -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    #[cfg(target_arch = "wasm32")]
    {
        let cfg = sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default();
        #[cfg(feature = "sqlite3mc")]
        let cfg = if matches!(opening, OpenRequest::Encrypted { .. }) {
            sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg {
                directory: ".opfs-sahpool-encrypted".into(),
                ..cfg
            }
        } else {
            cfg
        };
        let mut attempt = 0;
        loop {
            match sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
                .await
            {
                Ok(util) => {
                    SAH_POOL.with(|s| *s.borrow_mut() = Some(util));
                    break;
                }
                Err(e) if is_opfs_locked_error(&e) && attempt < OPFS_LOCK_RETRY_ATTEMPTS => {
                    attempt = attempt.saturating_add(1);
                    tracing::debug!(
                        attempt,
                        "[{WORKER_NAME}] OPFS SAH pool still locked by a previous worker, retrying"
                    );
                    TimeoutFuture::new(OPFS_LOCK_RETRY_DELAY_MS).await;
                }
                Err(e) => {
                    let error_details = format!("{e:?}");

                    let msg = if is_opfs_locked_error(&e) {
                        "Another tab or window is using this app's local database. Please close other tabs/windows running this app, then reload this page.".to_string()
                    } else {
                        "Failed to initialize local database storage.".to_string()
                    };

                    tracing::error!(details = %error_details, "[{WORKER_NAME}] fatal error installing OPFS Sqlite VFS");
                    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
                    return Err(JsError::new(&msg));
                }
            }
        }
    }

    // SAH installation replaces the default VFS. Attach MC's codec wrapper only
    // after it exists, including plaintext mode on an MC-enabled worker.
    #[cfg(all(target_arch = "wasm32", feature = "sqlite3mc"))]
    #[allow(unsafe_code)]
    {
        // SAFETY: the named VFS has just been registered in this worker. SQLite
        // owns the wrapper until all connections close and pause destroys it.
        let rc = unsafe { sqlite_wasm_rs::sqlite3mc_vfs_create(c"opfs-sahpool".as_ptr(), 1) };
        if rc != sqlite_wasm_rs::SQLITE_OK {
            return Err(JsError::new("Failed to register encrypted OPFS storage"));
        }
    }

    #[cfg(not(feature = "sqlite3mc"))]
    let opened = SqliteStorage::connect();
    #[cfg(feature = "sqlite3mc")]
    let opened = (|| -> anyhow::Result<SqliteStorage> {
        match opening {
            OpenRequest::Plaintext => {
                #[cfg(target_arch = "wasm32")]
                if SAH_POOL.with(|p| -> anyhow::Result<bool> {
                    Ok(p.borrow()
                        .as_ref()
                        .ok_or_else(|| anyhow!("OPFS unavailable"))?
                        .exists("spp.db")?)
                })? {
                    return SqliteStorage::connect_existing_plaintext("spp.db");
                }
                SqliteStorage::connect()
            }
            OpenRequest::Encrypted { key, purpose } => {
                #[cfg(target_arch = "wasm32")]
                {
                    SAH_POOL.with(|p| {
                        super::storage_migration::check_open(
                            p.borrow()
                                .as_ref()
                                .ok_or_else(|| anyhow!("OPFS unavailable"))?,
                            &key,
                            matches!(purpose, stellar_private_payments::state::database_key::OpenPurpose::CreateNew),
                        )?;
                        super::storage_backup::check_open(
                            p.borrow()
                                .as_ref()
                                .ok_or_else(|| anyhow!("OPFS unavailable"))?,
                        )
                    })?;
                    let exists = SAH_POOL.with(|p| -> anyhow::Result<bool> {
                        Ok(p.borrow()
                            .as_ref()
                            .ok_or_else(|| anyhow!("OPFS unavailable"))?
                            .exists("spp.encrypted.db")?)
                    })?;
                    anyhow::ensure!(exists == matches!(purpose, stellar_private_payments::state::database_key::OpenPurpose::OpenExisting), "database create/open purpose does not match existing file");
                }
                let storage = SqliteStorage::connect_encrypted("spp.encrypted.db", &key, purpose)?;
                #[cfg(target_arch = "wasm32")]
                SAH_POOL.with(|p| {
                    super::storage_backup::finish_open(
                        p.borrow()
                            .as_ref()
                            .ok_or_else(|| anyhow!("OPFS unavailable"))?,
                    )
                })?;
                Ok(storage)
            }
        }
    })();
    let storage = match opened {
        Ok(storage) => storage,
        Err(e) => {
            let msg = format!("Failed to open local database: {e}");
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
            return Err(JsError::new(&msg));
        }
    };

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });

    let (tx, rx) = mpsc::channel::<()>(1);

    PROCESSOR_TX.with(|cell| {
        *cell.borrow_mut() = Some(tx);
    });

    spawn_local(async move {
        run_processor_loop(rx).await;
    });

    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
    tracing::debug!("[{WORKER_NAME}] initialized");

    Ok(())
}

fn close_storage() {
    INIT_STATE
        .with(|s| *s.borrow_mut() = InitState::Failed("storage closed; open a new worker".into()));
    PROCESSOR_TX.with(|s| s.borrow_mut().take());
    STORAGE.with(|s| s.borrow_mut().take());
    #[cfg(all(target_arch = "wasm32", feature = "sqlite3mc"))]
    MIGRATION.with(|s| s.borrow_mut().take());
    #[cfg(all(target_arch = "wasm32", feature = "sqlite3mc"))]
    #[allow(unsafe_code)]
    unsafe {
        // SAFETY: this worker's sole SQLite connection has been dropped above.
        sqlite_wasm_rs::sqlite3mc_vfs_destroy(c"multipleciphers-opfs-sahpool".as_ptr());
    }
    #[cfg(target_arch = "wasm32")]
    SAH_POOL.with(|s| {
        if let Some(pool) = s.borrow().as_ref()
            && let Err(e) = pool.pause_vfs()
        {
            tracing::debug!("[{WORKER_NAME}] pause_vfs failed: {e:#}");
        }
    });
}

#[cfg(feature = "sqlite3mc")]
async fn open_requested(request: OpenRequest) -> Result<StorageWorkerResponse> {
    anyhow::ensure!(
        INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Locked)),
        "worker is already opening, open or closed"
    );
    if init(request).await.is_err() {
        close_storage();
        anyhow::bail!("database could not be opened; check its key and create/open policy");
    }
    Ok(StorageWorkerResponse::Saved)
}

#[oneshot]
pub(crate) async fn StorageWorker(
    req: CorrelatedRequest<StorageWorkerRequest>,
) -> StorageWorkerResponse {
    let correlation_id = req.correlation_id;
    let worker_span = tracing::info_span!(
        "worker_request",
        worker = WORKER_NAME,
        correlation_id = correlation_id.as_str()
    );
    async move {
        match router(req.payload).await {
            Ok(r) => r,
            Err(e) => StorageWorkerResponse::Error(e.to_string()),
        }
    }
    .instrument(worker_span)
    .await
}

// Main router of worker requests
pub(crate) async fn router(req: StorageWorkerRequest) -> Result<StorageWorkerResponse> {
    let resp = match req {
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::ExportEncrypted { key } => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = key;
                anyhow::bail!("encrypted snapshot requires OPFS");
            }
            #[cfg(target_arch = "wasm32")]
            {
                anyhow::ensure!(
                    INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Ready)),
                    "storage is not open"
                );
                anyhow::ensure!(key.0.len() == 32, "invalid database key");
                let mut owned =
                    stellar_private_payments::state::database_key::DatabaseKey::new([0; 32]);
                owned.copy_from_slice(&key.0);
                drop(key);
                // No await: SQLite writes and this snapshot execute serially in this worker.
                let bytes = SAH_POOL.with(|p| -> Result<Vec<u8>> {
                    let borrow = p.borrow();
                    let pool = borrow.as_ref().ok_or_else(|| anyhow!("OPFS unavailable"))?;
                    anyhow::ensure!(
                        pool.exists(super::storage_backup::DATABASE)?,
                        "encrypted database is not open"
                    );
                    let bytes = pool.export_db(super::storage_backup::DATABASE)?;
                    super::storage_backup::validate_export(pool, &owned, &bytes)?;
                    Ok(bytes)
                })?;
                StorageWorkerResponse::EncryptedSnapshot(bytes)
            }
        }
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::RestoreEncrypted { key, snapshot } => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = (key, snapshot);
                anyhow::bail!("encrypted restore requires OPFS");
            }
            #[cfg(target_arch = "wasm32")]
            {
                anyhow::ensure!(
                    INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Locked)),
                    "restore needs a fresh worker"
                );
                anyhow::ensure!(key.0.len() == 32, "invalid database key");
                let mut owned =
                    stellar_private_payments::state::database_key::DatabaseKey::new([0; 32]);
                owned.copy_from_slice(&key.0);
                drop(key);
                INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);
                let result = super::storage_backup::restore(&owned, &snapshot).await;
                INIT_STATE.with(|s| {
                    *s.borrow_mut() = InitState::Failed("restore worker finished".into())
                });
                result?;
                StorageWorkerResponse::Saved
            }
        }
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::OpenMigration {
            key,
            create_new,
            recover_setup,
        } => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = (key, create_new, recover_setup);
                anyhow::bail!("OPFS migration requires WASM");
            }
            #[cfg(target_arch = "wasm32")]
            {
                use stellar_private_payments::state::database_key::DatabaseKey;
                anyhow::ensure!(
                    INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Locked)),
                    "worker is already opening, open or closed"
                );
                anyhow::ensure!(key.0.len() == 32, "database key must contain 32 bytes");
                let mut owned = DatabaseKey::new([0; 32]);
                owned.copy_from_slice(&key.0);
                drop(key);
                INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);
                match super::storage_migration::BrowserMigration::open(
                    owned,
                    create_new,
                    recover_setup,
                )
                .await
                {
                    Ok(migration) => {
                        MIGRATION.with(|s| *s.borrow_mut() = Some(migration));
                        INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
                        StorageWorkerResponse::Saved
                    }
                    Err(_) => {
                        close_storage();
                        anyhow::bail!(
                            "migration could not be opened; check the key, source and create/open policy"
                        );
                    }
                }
            }
        }
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::Migration(action) => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = action;
                anyhow::bail!("OPFS migration requires WASM");
            }
            #[cfg(target_arch = "wasm32")]
            {
                let result = MIGRATION.with(|s| {
                    s.borrow_mut()
                        .as_mut()
                        .ok_or_else(|| anyhow!("migration is not open"))?
                        .action(action)
                });
                match result {
                    Ok(state) => StorageWorkerResponse::MigrationState(state),
                    Err(error) => {
                        // Failed OPFS writes can leave cached filename mappings
                        // ahead of durable state. Reacquire pools before retrying.
                        close_storage();
                        return Err(error);
                    }
                }
            }
        }
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::OpenPlaintext => return open_requested(OpenRequest::Plaintext).await,
        #[cfg(feature = "sqlite3mc")]
        StorageWorkerRequest::OpenEncrypted { key, create_new } => {
            use stellar_private_payments::state::database_key::{DatabaseKey, OpenPurpose};
            anyhow::ensure!(key.0.len() == 32, "database key must contain 32 bytes");
            let mut owned = DatabaseKey::new([0; 32]);
            owned.copy_from_slice(&key.0);
            drop(key);
            return open_requested(OpenRequest::Encrypted {
                key: owned,
                purpose: if create_new {
                    OpenPurpose::CreateNew
                } else {
                    OpenPurpose::OpenExisting
                },
            })
            .await;
        }
        StorageWorkerRequest::Pause => {
            tracing::debug!("[{WORKER_NAME}] pausing OPFS SAH pool ahead of page unload");
            // `pause_vfs` refuses to release handles while SQLite still has
            // files open on this VFS, so the live connection must be closed
            // first — this worker is about to be torn down by the browser
            // anyway, and any in-flight request will simply fail from here on.
            close_storage();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::Ping => {
            tracing::trace!("[{WORKER_NAME}] ping");
            loop {
                let state = INIT_STATE.with(|s| s.borrow().clone());
                match state {
                    InitState::Ready => {
                        tracing::trace!("[{WORKER_NAME}] pong");
                        kick_processor();
                        return Ok(StorageWorkerResponse::Pong);
                    }
                    InitState::Failed(msg) => {
                        tracing::debug!("[{WORKER_NAME}] ping -> init failed");
                        return Ok(StorageWorkerResponse::Error(msg));
                    }
                    InitState::Pending => {}
                    #[cfg(feature = "sqlite3mc")]
                    InitState::Locked => return Err(anyhow!("storage has not been opened")),
                }

                TimeoutFuture::new(50).await;
            }
        }
        StorageWorkerRequest::SyncState => {
            tracing::trace!("[{WORKER_NAME}] get current sync");
            let state = with_storage!(s => s.get_sync_metadata()?)?;
            let resp = StorageWorkerResponse::SyncState(state);
            tracing::trace!("[{WORKER_NAME}] sending current sync");
            resp
        }
        StorageWorkerRequest::ProcessPendingState => {
            tracing::trace!("[{WORKER_NAME}] processing pending state");
            process_until_empty().await?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::SaveEvents(events_data) => {
            tracing::trace!(
                "[{WORKER_NAME}] saving {} raw contract events",
                events_data.events.len()
            );
            with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            tracing::trace!(
                "[{WORKER_NAME}] sending {} raw contract events to process",
                events_data.events.len()
            );
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::SaveSyncProgress {
            metadata,
            fully_indexed,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] saving bulk sync progress for {} contracts (fully_indexed={fully_indexed})",
                metadata.len()
            );
            with_storage_mut!(s => s.save_sync_progress(&metadata, fully_indexed)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClearIndexingCursors => {
            tracing::trace!("[{WORKER_NAME}] clearing indexing cursors for RPC handoff");
            with_storage_mut!(s => s.clear_indexing_cursors()?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClampLastFullyIndexedLedger(max_ledger) => {
            tracing::trace!("[{WORKER_NAME}] clamping last_fully_indexed_ledger to {max_ledger}");
            with_storage_mut!(s => s.clamp_last_fully_indexed_ledger(max_ledger)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DeriveSaveUserKeys(address, signature, network_context) => {
            tracing::trace!(
                "[{WORKER_NAME}] deriving and saving user keys for the account {}",
                Sensitive(&address)
            );
            let (note_keypair, encryption_keypair) =
                derive_encryption_and_note_keypairs(signature.clone())?;
            let membership_blinding = derive_membership_blinding(&signature, &network_context)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair, &membership_blinding)?)?;
            tracing::trace!(
                "[{WORKER_NAME}] saved notes, encryption keys, and ASP secret for the account {}",
                Sensitive(&address)
            );
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DisclaimerState(address) => {
            tracing::trace!(
                "[{WORKER_NAME}] disclaimer state for account {}",
                Sensitive(&address)
            );
            let state = with_storage_mut!(s => s.get_disclaimer_state(&address)?)?;
            StorageWorkerResponse::DisclaimerState(DisclaimerStatePayload {
                disclaimer_text_md: state.disclaimer_text_md,
                disclaimer_hash_hex: state.disclaimer_hash_hex,
                accepted: state.accepted,
            })
        }
        StorageWorkerRequest::AcceptDisclaimer(address, disclaimer_hash_hex) => {
            tracing::trace!(
                "[{WORKER_NAME}] accept disclaimer for account {}",
                Sensitive(&address)
            );
            with_storage_mut!(s => s.accept_current_disclaimer(&address, &disclaimer_hash_hex)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::GetSetting(key) => {
            tracing::trace!("[{WORKER_NAME}] fetch setting {key}");
            let value_json = with_storage!(s => s.get_setting_json::<serde_json::Value>(&key)?)?
                .map(|value| value.to_string());
            StorageWorkerResponse::Setting(value_json)
        }
        StorageWorkerRequest::SetSetting { key, value_json } => {
            tracing::trace!("[{WORKER_NAME}] set setting {key}");
            let value: serde_json::Value = serde_json::from_str(&value_json)?;
            with_storage_mut!(s => s.set_setting_json(&key, &value)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UserKeys(address) => {
            tracing::trace!(
                "[{WORKER_NAME}] fetch user keys for the account {}",
                Sensitive(&address)
            );
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            if opt.is_some() {
                tracing::trace!(
                    "[{WORKER_NAME}] fetched notes and encryption keys for the account {}",
                    Sensitive(&address)
                );
            } else {
                tracing::trace!(
                    "[{WORKER_NAME}] not found notes and encryption keys for the account {}",
                    Sensitive(&address)
                );
            }
            StorageWorkerResponse::UserKeys(opt.map(|keys| UserKeys {
                note_keypair: PublicNoteKeyPair {
                    public: keys.note_keypair.public,
                },
                encryption_keypair: PublicEncryptionKeyPair {
                    public: keys.encryption_keypair.public,
                },
            }))
        }
        StorageWorkerRequest::AspSecret(address) => {
            tracing::trace!(
                "[{WORKER_NAME}] fetch ASP secret for the account {}",
                Sensitive(&address)
            );
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            StorageWorkerResponse::AspSecret(opt.map(|keys| AspSecret {
                membership_blinding: keys.membership_blinding,
            }))
        }
        StorageWorkerRequest::UserNotes(address, limit) => {
            tracing::trace!(
                "[{WORKER_NAME}] list user notes for the account {}",
                Sensitive(&address)
            );
            let list = with_storage!(s => s.list_user_notes(&address, limit)?)?;
            tracing::trace!(
                "[{WORKER_NAME}] fetched {} notes for the account {}",
                list.len(),
                Sensitive(&address)
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::PortfolioBalances {
            address,
            enabled_pools,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] list portfolio balances for the account {}",
                Sensitive(&address)
            );
            let list = with_storage!(s => s.list_portfolio_balances(&address, &enabled_pools)?)?;
            StorageWorkerResponse::PortfolioBalances(list)
        }
        StorageWorkerRequest::RecordOperation {
            address,
            pool_contract_id,
            op_type,
            amount,
            direction,
            counterparty,
            tx_hash,
        } => {
            with_storage!(s => s.insert_operation(
                &address,
                &pool_contract_id,
                &op_type,
                &amount,
                &direction,
                counterparty.as_deref(),
                tx_hash.as_deref(),
            )?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ListOperations {
            address,
            pool_contract_id,
            limit,
        } => {
            let list = with_storage!(s => s.list_operations(&address, &pool_contract_id, limit)?)?;
            StorageWorkerResponse::Operations(list)
        }
        StorageWorkerRequest::UnspentUserNotes {
            user_address,
            pool_contract_id,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] list all unspent notes for the account {} in pool {pool_contract_id}",
                Sensitive(&user_address)
            );
            let list = with_storage!(s =>
                s.list_unspent_user_notes(&pool_contract_id, &user_address)?
            )?;
            tracing::trace!(
                "[{WORKER_NAME}] fetched {} unspent notes for the account {}",
                list.len(),
                Sensitive(&user_address)
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::PoolUserNotes {
            user_address,
            pool_contract_id,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] list all notes for the account {} in pool {pool_contract_id}",
                Sensitive(&user_address)
            );
            let list = with_storage!(s =>
                s.list_pool_user_notes(&pool_contract_id, &user_address)?
            )?;
            tracing::trace!(
                "[{WORKER_NAME}] fetched {} notes for the account {}",
                list.len(),
                Sensitive(&user_address)
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::RecipientLookup {
            address,
            public_key_registry_contract_id,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] lookup public keys for {}",
                Sensitive(&address)
            );
            let lookup = with_storage!(s =>
                s.recipient_lookup(&address, &public_key_registry_contract_id)?
            )?;
            StorageWorkerResponse::RecipientLookup(lookup)
        }
        StorageWorkerRequest::OperationalFeed {
            limit,
            asp_membership_contract_id,
            public_key_registry_contract_id,
        } => {
            tracing::trace!("[{WORKER_NAME}] fetch operational feed");
            let list = with_storage!(s =>
                s.get_operational_feed(
                    limit,
                    &asp_membership_contract_id,
                    &public_key_registry_contract_id,
                )?
            )?;
            StorageWorkerResponse::OperationalFeed(list)
        }
        StorageWorkerRequest::DisclosureInputs(req) => {
            tracing::trace!(
                "[{WORKER_NAME}] build selective disclosure inputs for {}",
                Sensitive(&req.user_address)
            );

            with_storage_mut!(storage => match build_disclosure_inputs(storage, &req)? {
                BuildDisclosureInputs::Ready(notes) => {
                    StorageWorkerResponse::DisclosureNotes(notes)
                }
                BuildDisclosureInputs::MembershipSync(status) => {
                    StorageWorkerResponse::AspMembershipSync(status)
                }
            })?
        }
        StorageWorkerRequest::DeriveASPleaf(AdminASPRequest {
            membership_blinding,
            pubkey,
        }) => {
            tracing::trace!("[{WORKER_NAME}] derive user leaf from the pubkey for the admin");
            let user_leaf = asp_membership_leaf(&pubkey, &membership_blinding)?;
            tracing::trace!("[{WORKER_NAME}] derived user leaf from the pubkey for the admin");
            StorageWorkerResponse::DeriveASPleaf(user_leaf)
        }
        StorageWorkerRequest::ConfigureTelemetry(config) => {
            let _ = crate::telemetry::set_log_level(&config.level);
            stellar_private_payments::types::set_reveal_sensitive(config.reveal_sensitive);
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DumpLogs => {
            StorageWorkerResponse::Logs(crate::telemetry::dump_recent_logs())
        }
        StorageWorkerRequest::Transact(req) => {
            tracing::trace!("[{WORKER_NAME}] transact");
            with_storage_mut!(storage => match build_transact_params(storage, &req)? {
                BuildTransactParams::Ready(params) => StorageWorkerResponse::TransactParams(*params),
                BuildTransactParams::MembershipSync(status) => {
                    StorageWorkerResponse::AspMembershipSync(status)
                }
            })?
        }
        StorageWorkerRequest::ListPoolGvkEvents {
            pool_contract_id,
            after,
            limit,
        } => {
            tracing::trace!("[{WORKER_NAME}] list pool gvk events for {pool_contract_id}");
            let events =
                with_storage!(s => s.list_pool_gvk_events(&pool_contract_id, after, limit)?)?;
            StorageWorkerResponse::PoolGvkEvents(events)
        }
        StorageWorkerRequest::PoolHasCommitments {
            pool_contract_id,
            commitments,
        } => {
            tracing::trace!(
                "[{WORKER_NAME}] verify {} pool commitment(s) for {pool_contract_id}",
                commitments.len()
            );
            let found = with_storage!(s =>
                s.pool_has_commitments(&pool_contract_id, &commitments)?
            )?;
            StorageWorkerResponse::PoolHasCommitments(found.into_iter().collect())
        }
    };
    Ok(resp)
}

fn kick_processor() {
    PROCESSOR_TX.with(|cell| {
        if let Some(tx) = cell.borrow_mut().as_mut() {
            let _ = tx.try_send(());
        }
    });
}

async fn run_processor_loop(mut rx: mpsc::Receiver<()>) {
    while let Some(()) = rx.next().await {
        if let Err(e) = process_until_empty().await {
            tracing::error!("[{WORKER_NAME}] events processing failed: {e:#}");
        }
    }
}

async fn process_until_empty() -> anyhow::Result<()> {
    loop {
        let did_work = with_storage_mut!(storage => process_local_state_batch(storage)?)?;
        if !did_work {
            break;
        }
        TimeoutFuture::new(0).await;
    }
    Ok(())
}

/// Storage worker bridge — single entry point for all main-thread ↔ worker I/O.
pub(crate) struct StorageBridge {
    bridge: OneshotBridge<StorageWorker>,
}

impl Clone for StorageBridge {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.fork(),
        }
    }
}

impl StorageBridge {
    pub(crate) fn new(bridge: OneshotBridge<StorageWorker>) -> Self {
        Self { bridge }
    }

    /// Copy duration depends on database size. Migration commands have no
    /// request timer; callers can terminate the worker and resume durable state.
    #[cfg(feature = "sqlite3mc")]
    pub(crate) async fn call_without_timeout(
        &self,
        req: StorageWorkerRequest,
    ) -> anyhow::Result<StorageWorkerResponse> {
        let request = CorrelatedRequest {
            correlation_id: crate::correlation::current_correlation_id()
                .unwrap_or_else(|| "-".into()),
            payload: req,
        };
        match self.bridge.fork().run(request).await {
            StorageWorkerResponse::Error(e) => Err(anyhow!(e)),
            other => Ok(other),
        }
    }

    pub(crate) async fn call(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> anyhow::Result<StorageWorkerResponse> {
        let correlated_req = CorrelatedRequest {
            correlation_id: crate::correlation::current_correlation_id()
                .unwrap_or_else(|| "-".to_string()),
            payload: req,
        };
        let mut bridge = self.bridge.fork();
        let fut = bridge.run(correlated_req).fuse();
        let timeout = TimeoutFuture::new(timeout_ms).fuse();

        futures::pin_mut!(fut, timeout);

        let resp = futures::select! {
            value = fut => value,
            _ = timeout => {
                return Err(anyhow!("operation timed out after {timeout_ms} ms"));
            }
        };

        match resp {
            StorageWorkerResponse::Error(e) => Err(anyhow!(e)),
            other => Ok(other),
        }
    }

    pub(crate) async fn ping(&self) -> anyhow::Result<()> {
        self.ping_ms(5_000).await
    }

    pub(crate) async fn ping_ms(&self, timeout_ms: u32) -> anyhow::Result<()> {
        match self.call(StorageWorkerRequest::Ping, timeout_ms).await? {
            StorageWorkerResponse::Pong => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl ContractDataStorage for StorageBridge {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        match self.call(StorageWorkerRequest::SyncState, 5_000).await? {
            StorageWorkerResponse::SyncState(state) => Ok(state),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }

    async fn save_events_batch(&self, data: ContractsEventData) -> anyhow::Result<()> {
        match self
            .call(StorageWorkerRequest::SaveEvents(data), 10_000)
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        match self
            .call(
                StorageWorkerRequest::SaveSyncProgress {
                    metadata,
                    fully_indexed,
                },
                10_000,
            )
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Storage for StorageBridge {
    fn fork(&self) -> Result<Self, Error> {
        Ok(Self {
            bridge: self.bridge.fork(),
        })
    }

    async fn process_pending_state(&self) -> Result<(), Error> {
        match self
            .call(StorageWorkerRequest::ProcessPendingState, 30_000)
            .await
        {
            Ok(StorageWorkerResponse::Saved) => Ok(()),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected process_pending_state response: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn clear_indexing_cursors(&self) -> Result<(), Error> {
        match self
            .call(StorageWorkerRequest::ClearIndexingCursors, 2_000)
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(Error::Other(anyhow::anyhow!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error> {
        match self
            .call(
                StorageWorkerRequest::ClampLastFullyIndexedLedger(max_ledger),
                2_000,
            )
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(Error::Other(anyhow::anyhow!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        Ok(self.ping().await?)
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, Error> {
        match self
            .call(
                StorageWorkerRequest::UnspentUserNotes {
                    user_address: user_address.to_string(),
                    pool_contract_id: pool_contract_id.to_string(),
                },
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::UserNotes(notes)) => Ok(notes
                .into_iter()
                .map(|n| SpendableNote {
                    commitment: n.id,
                    amount: n.amount,
                })
                .collect()),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading spendable notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        match self
            .call(
                StorageWorkerRequest::PoolUserNotes {
                    user_address: user_address.to_string(),
                    pool_contract_id: pool_contract_id.to_string(),
                },
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::UserNotes(notes)) => Ok(notes),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        enabled_pools: &[PortfolioPoolEntry],
    ) -> Result<Vec<PortfolioBalance>, Error> {
        match self
            .call(
                StorageWorkerRequest::PortfolioBalances {
                    address: user_address.to_string(),
                    enabled_pools: enabled_pools.to_vec(),
                },
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PortfolioBalances(balances)) => Ok(balances),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading portfolio balances: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn list_user_notes(
        &self,
        user_address: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        match self
            .call(
                StorageWorkerRequest::UserNotes(user_address.to_string(), limit),
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::UserNotes(notes)) => Ok(notes),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading user notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn operational_feed(
        &self,
        limit: u32,
        config: &ContractConfig,
    ) -> Result<Vec<OperationalFeedItem>, Error> {
        match self
            .call(
                StorageWorkerRequest::OperationalFeed {
                    limit,
                    asp_membership_contract_id: config.asp_membership.clone(),
                    public_key_registry_contract_id: config.public_key_registry.clone(),
                },
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::OperationalFeed(list)) => Ok(list),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading operational feed: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn recipient_lookup(
        &self,
        address: &str,
        config: &ContractConfig,
    ) -> Result<RecipientLookup, Error> {
        match self
            .call(
                StorageWorkerRequest::RecipientLookup {
                    address: address.to_string(),
                    public_key_registry_contract_id: config.public_key_registry.clone(),
                },
                2_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::RecipientLookup(lookup)) => Ok(lookup),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response looking up recipient: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error> {
        match self
            .call(StorageWorkerRequest::Transact(req.clone()), 5_000)
            .await
        {
            Ok(StorageWorkerResponse::TransactParams(params)) => Ok(params),
            Ok(StorageWorkerResponse::AspMembershipSync(status)) => {
                Err(Error::MembershipSync(status))
            }
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response building transact params: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error> {
        match self
            .call(StorageWorkerRequest::DisclosureInputs(req.clone()), 5_000)
            .await
        {
            Ok(StorageWorkerResponse::DisclosureNotes(notes)) => Ok(notes),
            Ok(StorageWorkerResponse::AspMembershipSync(status)) => {
                Err(Error::MembershipSync(status))
            }
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response building disclosure inputs: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, Error> {
        let _ = user_address;
        Err(Error::Other(anyhow::anyhow!(
            "full stored user keys are not available on the storage bridge; use asp_secret"
        )))
    }

    async fn asp_secret(&self, user_address: &str) -> Result<Field, Error> {
        match self
            .call(
                StorageWorkerRequest::AspSecret(user_address.to_string()),
                1_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::AspSecret(secret)) => secret
                .ok_or_else(|| {
                    Error::Other(anyhow::anyhow!("ASP secret not found in worker storage"))
                })
                .map(|asp| asp.membership_blinding),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading ASP secret: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        match self
            .call(
                StorageWorkerRequest::UserKeys(user_address.to_string()),
                1_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::UserKeys(keys)) => {
                let keys = keys.ok_or_else(|| {
                    Error::Other(anyhow::anyhow!("user keys not found in worker storage"))
                })?;
                Ok((keys.note_keypair.public, keys.encryption_keypair.public))
            }
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading user keys: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, Error> {
        Ok(self.user_public_keys(user_address).await?.0)
    }

    async fn registered_public_keys(
        &self,
        address: &str,
        public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        match self
            .call(
                StorageWorkerRequest::RecipientLookup {
                    address: address.to_string(),
                    public_key_registry_contract_id: public_key_registry_contract_id.to_string(),
                },
                2_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::RecipientLookup(lookup)) => {
                let entry = lookup.entry.ok_or_else(|| {
                    Error::Other(anyhow::anyhow!(
                        "recipient {address} not found in the public key registry; \
                         they must register keys on-chain"
                    ))
                })?;
                Ok((entry.note_key, entry.encryption_key))
            }
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response looking up recipient: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn list_pool_gvk_events(
        &self,
        pool_contract_id: &str,
        after: Option<(u32, String)>,
        limit: u32,
    ) -> Result<Vec<stellar_private_payments::gvk::GvkEvent>, Error> {
        match self
            .call(
                StorageWorkerRequest::ListPoolGvkEvents {
                    pool_contract_id: pool_contract_id.to_string(),
                    after,
                    limit,
                },
                30_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PoolGvkEvents(events)) => Ok(events),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response listing pool gvk events: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn pool_has_commitments(
        &self,
        pool_contract_id: &str,
        commitments: &[stellar_private_payments::types::Field],
    ) -> Result<std::collections::HashSet<stellar_private_payments::types::Field>, Error> {
        match self
            .call(
                StorageWorkerRequest::PoolHasCommitments {
                    pool_contract_id: pool_contract_id.to_string(),
                    commitments: commitments.to_vec(),
                },
                30_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PoolHasCommitments(found)) => Ok(found.into_iter().collect()),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response verifying pool commitments: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn dump_logs_returns_ring_buffer_contents() {
        crate::telemetry::init_telemetry(None);
        let resp = futures::executor::block_on(router(StorageWorkerRequest::DumpLogs))
            .expect("dump logs succeeds");
        let StorageWorkerResponse::Logs(_) = resp else {
            panic!("expected Logs response, got: {resp:?}");
        };
    }
}

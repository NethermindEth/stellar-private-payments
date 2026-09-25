use crate::{
    telemetry::WorkerTelemetryConfig,
    workers::{CorrelatedRequest, StorageHandle},
};
use anyhow::{Result, anyhow};
use futures::{FutureExt, channel::mpsc, stream::StreamExt};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use stellar_private_payments::{
    Error, Storage,
    chain::ContractDataStorage,
    disclosure::{
        BuildDisclosureInputs, DisclosureInputs, DisclosureInputsRequest, build_disclosure_inputs,
    },
    gvk::GvkEvent,
    planner::SpendableNote,
    state::{SqliteStorage, process_local_state_batch},
    transact::{BuildTransactParams, TransactRequest, build_transact_params},
    types::{
        AspMembershipSync, ContractConfig, ContractsEventData, EncryptionKeyPair,
        EncryptionPublicKey, Field, NoteKeyPair, NotePublicKey, OperationalFeedItem,
        PortfolioBalance, PortfolioPoolEntry, RecipientLookup, Sensitive, SyncMetadata,
        UserNoteSummary, UserOperation,
    },
    zk::{crypto::asp_membership_leaf, flows::TransactParams},
};
use tracing::Instrument;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

#[cfg(target_arch = "wasm32")]
use gloo_worker::Spawnable;

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

type Address = String;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicNoteKeyPair {
    public: NotePublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicEncryptionKeyPair {
    public: EncryptionPublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrivacyKeys {
    note_keypair: PublicNoteKeyPair,
    encryption_keypair: PublicEncryptionKeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AspSecret {
    membership_blinding: Field,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DisclaimerStatePayload {
    disclaimer_text_md: String,
    disclaimer_hash_hex: String,
    accepted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminASPRequest {
    membership_blinding: Field,
    pubkey: NotePublicKey,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StorageWorkerRequest {
    Ping,
    Pause,
    SyncState,
    ProcessPendingState,
    SaveEvents(ContractsEventData),
    SaveSyncProgress {
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    },
    ClearIndexingCursors,
    ClampLastFullyIndexedLedger(u32),
    SavePrivateKeys(Address, NoteKeyPair, EncryptionKeyPair, Field),
    DisclaimerState(Address),
    AcceptDisclaimer(Address, String),
    GetSetting(String),
    SetSetting {
        key: String,
        value_json: String,
    },
    PrivacyKeys(Address),
    AspSecret(Address),
    UserNotes(Address, u32),
    PortfolioBalances {
        address: Address,
        enabled_pools: Vec<PortfolioPoolEntry>,
    },
    RecordOperation {
        address: Address,
        pool_contract_id: String,
        op_type: String,
        amount: String,
        direction: String,
        counterparty: Option<String>,
        tx_hash: Option<String>,
    },
    ListOperations {
        address: Address,
        pool_contract_id: String,
        limit: u32,
    },
    UnspentUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    PoolUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    RecipientLookup {
        address: Address,
        public_key_registry_contract_id: String,
    },
    OperationalFeed {
        limit: u32,
        asp_membership_contract_id: String,
        public_key_registry_contract_id: String,
    },
    DisclosureInputs(DisclosureInputsRequest),
    Transact(TransactRequest),
    DeriveASPleaf(AdminASPRequest),
    ConfigureTelemetry(WorkerTelemetryConfig),
    DumpLogs,
    ListPoolGvkEvents {
        pool_contract_id: String,
        after: Option<(u32, String)>,
        limit: u32,
    },
    PoolHasCommitments {
        pool_contract_id: String,
        commitments: Vec<Field>,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StorageWorkerResponse {
    Pong,
    SyncState(Vec<SyncMetadata>),
    Saved,
    Error(String),
    DisclaimerState(DisclaimerStatePayload),
    Setting(Option<String>),
    PrivacyKeys(Option<PrivacyKeys>),
    AspSecret(Option<AspSecret>),
    UserNotes(Vec<UserNoteSummary>),
    PortfolioBalances(Vec<PortfolioBalance>),
    Operations(Vec<UserOperation>),
    RecipientLookup(RecipientLookup),
    OperationalFeed(Vec<OperationalFeedItem>),
    AspMembershipSync(AspMembershipSync),
    DisclosureNotes(Vec<DisclosureInputs>),
    TransactParams(TransactParams),
    DeriveASPleaf(Field),
    Logs(String),
    PoolGvkEvents(Vec<GvkEvent>),
    PoolHasCommitments(Vec<Field>),
}

#[derive(Clone, Debug)]
enum InitState {
    Pending,
    Ready,
    Failed(String),
}

#[cfg(target_arch = "wasm32")]
fn is_opfs_locked_error(err: &sqlite_wasm_vfs::sahpool::OpfsSAHError) -> bool {
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
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Pending) };
    #[cfg(target_arch = "wasm32")]
    static SAH_POOL: RefCell<Option<sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil>> = const { RefCell::new(None) };
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

async fn init() -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    #[cfg(target_arch = "wasm32")]
    {
        let mut attempt = 0;
        loop {
            match sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
                &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
                true,
            )
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

    let storage = match SqliteStorage::connect() {
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
        StorageWorkerRequest::Pause => {
            tracing::debug!("[{WORKER_NAME}] pausing OPFS SAH pool ahead of page unload");
            // `pause_vfs` refuses to release handles while SQLite still has
            // files open on this VFS, so the live connection must be closed
            // first — this worker is about to be torn down by the browser
            // anyway, and any in-flight request will simply fail from here on.
            let dropped_storage = STORAGE.with(|s| s.borrow_mut().take());
            drop(dropped_storage);
            #[cfg(target_arch = "wasm32")]
            SAH_POOL.with(|s| {
                if let Some(pool) = s.borrow().as_ref()
                    && let Err(e) = pool.pause_vfs()
                {
                    tracing::debug!("[{WORKER_NAME}] pause_vfs failed: {e:#}");
                }
            });
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
        StorageWorkerRequest::SavePrivateKeys(
            address,
            note_keypair,
            encryption_keypair,
            membership_blinding,
        ) => {
            tracing::trace!(
                "[{WORKER_NAME}] saving private keys for the account {}",
                Sensitive(&address)
            );
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
        StorageWorkerRequest::PrivacyKeys(address) => {
            tracing::trace!(
                "[{WORKER_NAME}] fetch privacy keys for the account {}",
                Sensitive(&address)
            );
            let opt = with_storage!(s => s.get_private_keys(&address)?)?;
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
            StorageWorkerResponse::PrivacyKeys(opt.map(|keys| PrivacyKeys {
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
            let opt = with_storage!(s => s.get_private_keys(&address)?)?;
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

#[cfg(target_arch = "wasm32")]
pub(crate) const DEFAULT_STORAGE_WORKER_URL: &str = "./workers/storage-worker.js";
#[cfg(target_arch = "wasm32")]
const DEFAULT_CALL_TIMEOUT_MS: u32 = 5_000;
/// Cold wasm compile + OPFS/SQLite init can exceed the default RPC timeout.
#[cfg(target_arch = "wasm32")]
const STORAGE_OPEN_PING_TIMEOUT_MS: u32 = 15_000;

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOptions {
    worker_url: Option<String>,
}

/// Storage worker bridge — main-thread ↔ worker I/O for local persistence.
/// Open once per page, [`StorageBridge::fork`] for extra handles.
#[wasm_bindgen(js_name = Storage)]
#[cfg(target_arch = "wasm32")]
pub struct StorageBridge {
    bridge: OneshotBridge<StorageWorker>,
}

#[cfg(target_arch = "wasm32")]
impl Clone for StorageBridge {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.fork(),
        }
    }
}

#[wasm_bindgen(js_class = Storage)]
#[cfg(target_arch = "wasm32")]
impl StorageBridge {
    /// Spawn the storage worker and verify it is ready.
    ///
    /// Call once per page session. Use [`StorageBridge::fork`] for additional
    /// handles (e.g. app code alongside [`crate::Client`]).
    #[wasm_bindgen(js_name = open)]
    pub async fn open(options: JsValue) -> Result<StorageBridge, JsError> {
        let opts: OpenOptions = if options.is_null() || options.is_undefined() {
            OpenOptions { worker_url: None }
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        Self::open_internal(
            opts.worker_url
                .unwrap_or_else(|| DEFAULT_STORAGE_WORKER_URL.to_string()),
        )
        .await
    }

    /// New handle to the same storage worker (shared `spp.db`).
    #[wasm_bindgen(js_name = fork)]
    pub fn fork_js(&self) -> StorageBridge {
        self.clone()
    }

    /// Forks and pings before converting to a [`StorageHandle`].
    #[wasm_bindgen(js_name = toHandle)]
    pub async fn to_handle(&self) -> Result<StorageHandle, JsError> {
        let bridge = self.clone();
        bridge
            .ping()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(StorageHandle::new(bridge.into()))
    }

    /// Raw storage-worker RPC. Request/response shapes match the worker
    /// protocol (externally tagged enums, e.g. `{ "DisclaimerState": "G..."
    /// }`).
    #[wasm_bindgen(js_name = call)]
    pub async fn call_js(
        &self,
        request: JsValue,
        timeout_ms: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let req: StorageWorkerRequest = serde_wasm_bindgen::from_value(request)?;
        let timeout = timeout_ms.unwrap_or(DEFAULT_CALL_TIMEOUT_MS);
        let resp = self
            .call(req, timeout)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&resp)?)
    }
}

#[cfg(target_arch = "wasm32")]
impl StorageBridge {
    pub(crate) fn new(bridge: OneshotBridge<StorageWorker>) -> Self {
        Self { bridge }
    }

    async fn open_internal(worker_url: String) -> Result<Self, JsError> {
        crate::wasm_start();

        let storage = Self::new(
            StorageWorker::spawner()
                .with_loader(true)
                .as_module(true)
                .spawn(&worker_url),
        );

        storage
            .ping_ms(STORAGE_OPEN_PING_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(storage)
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

#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl Storage for StorageBridge {
    fn fork(&self) -> Result<stellar_private_payments::StorageHandle, Error> {
        let forked = Self {
            bridge: self.bridge.fork(),
        };
        Ok(forked.into())
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

    async fn privacy_keys_exist(&self, user_address: &str) -> Result<bool, Error> {
        match self
            .call(
                StorageWorkerRequest::PrivacyKeys(user_address.to_string()),
                1_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PrivacyKeys(keys)) => Ok(keys.is_some()),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response checking user keys: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn save_private_keys(
        &self,
        user_address: &str,
        note_keypair: &NoteKeyPair,
        encryption_keypair: &EncryptionKeyPair,
        membership_blinding: &Field,
    ) -> Result<(), Error> {
        match self
            .call(
                StorageWorkerRequest::SavePrivateKeys(
                    user_address.to_string(),
                    note_keypair.clone(),
                    encryption_keypair.clone(),
                    *membership_blinding,
                ),
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::Saved) => Ok(()),
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response saving user keys: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
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

    async fn privacy_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        match self
            .call(
                StorageWorkerRequest::PrivacyKeys(user_address.to_string()),
                1_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PrivacyKeys(keys)) => {
                let keys = keys.ok_or_else(|| Error::PrivacyKeysNotFound {
                    user_address: user_address.to_string(),
                })?;
                Ok((keys.note_keypair.public, keys.encryption_keypair.public))
            }
            Ok(other) => Err(Error::Other(anyhow::anyhow!(
                "unexpected storage response loading privacy keys: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e)),
        }
    }

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, Error> {
        Ok(self.privacy_keys(user_address).await?.0)
    }

    async fn registered_privacy_keys(
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

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn dump_logs_returns_ring_buffer_contents() {
        crate::telemetry::init_telemetry(None);
        let resp = router(StorageWorkerRequest::DumpLogs)
            .await
            .expect("dump logs succeeds");
        let StorageWorkerResponse::Logs(_) = resp else {
            panic!("expected Logs response, got: {resp:?}");
        };
    }
}

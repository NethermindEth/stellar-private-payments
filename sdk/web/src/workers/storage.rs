use crate::protocol::{
    AdminASPRequest, AspSecret, CorrelatedRequest, DisclaimerStatePayload, DisclosureInputs,
    DisclosureInputsRequest, PrivacyKeys, PublicEncryptionKeyPair, PublicNoteKeyPair,
    StorageWorkerRequest, StorageWorkerResponse,
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
    state::{SqliteStorage, process_local_state_batch},
    transact::{BuildTransactParams, TransactRequest, build_transact_params},
    types::{
        ContractConfig, ContractsEventData, EncryptionKeyPair, EncryptionPublicKey, Field,
        NoteKeyPair, NotePublicKey, OperationalFeedItem, PortfolioBalance, PortfolioPoolEntry,
        RecipientLookup, Sensitive, SyncMetadata, UserNoteSummary,
    },
    zk::{crypto::asp_membership_leaf, flows::TransactParams},
};
use tracing::Instrument;
use wasm_bindgen_futures::spawn_local;

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

#[derive(Clone, Debug)]
enum InitState {
    Locked,
    Pending,
    Ready,
    Failed(String),
}

thread_local! {
    static PUBLIC_STORAGE: RefCell<Option<SqliteStorage>> = const { RefCell::new(None) };
    static STORAGE: RefCell<Option<SqliteStorage>> = const { RefCell::new(None) };
    static PROCESSOR_TX: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Locked) };
}

macro_rules! with_connection {
    ($cell:ident, $borrow:ident, $access:ident, $storage:ident => $body:expr) => {
        $cell.with(|cell| {
            let mut borrow = cell.$borrow();
            let $storage = borrow
                .$access()
                .ok_or_else(|| anyhow!("storage is not initialized"))?;
            Ok::<_, anyhow::Error>($body)
        })
    };
}

macro_rules! with_storage {
    ($storage:ident => $body:expr) => {
        with_connection!(STORAGE, borrow_mut, as_mut, $storage => $body)
    };
}
macro_rules! with_storage_mut {
    ($storage:ident => $body:expr) => {
        with_storage!($storage => $body)
    };
}
macro_rules! with_public {
    ($storage:ident => $body:expr) => {
        with_connection!(PUBLIC_STORAGE, borrow_mut, as_mut, $storage => $body)
    };
}
macro_rules! with_public_mut {
    ($storage:ident => $body:expr) => {
        with_public!($storage => $body)
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
}

/// Serve `storage`, which has just been created or unlocked.
fn start(storage: SqliteStorage) {
    STORAGE.with(|s| *s.borrow_mut() = Some(storage));
    start_processor();
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
    kick_processor();
    tracing::debug!("[{WORKER_NAME}] initialized");
}

fn start_processor() {
    if PROCESSOR_TX.with(|cell| cell.borrow().is_some()) {
        return;
    }
    let (tx, rx) = mpsc::channel::<()>(1);
    PROCESSOR_TX.with(|cell| *cell.borrow_mut() = Some(tx));
    spawn_local(async move {
        run_processor_loop(rx).await;
    });
}

/// Stop serving the database, keeping the OPFS pools for another open.
fn detach() {
    super::storage_access::clear_recovery_key();
    PROCESSOR_TX.with(|s| s.borrow_mut().take());
    STORAGE.with(|s| s.borrow_mut().take());
    PUBLIC_STORAGE.with(|s| s.borrow_mut().take());
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Locked);
}

fn close_storage() {
    detach();
    INIT_STATE
        .with(|s| *s.borrow_mut() = InitState::Failed("storage closed; open a new worker".into()));
    super::storage_access::release();
}

/// Create or unlock the database while no other open is in progress. A
/// failure leaves the worker locked, so the user can try again.
async fn open_with(
    open: impl std::future::Future<Output = Result<Option<SqliteStorage>>>,
) -> Result<StorageWorkerResponse> {
    anyhow::ensure!(
        INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Locked)),
        "the database is already open, opening or closed"
    );
    super::storage_access::clear_recovery_key();
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);
    match open.await {
        Ok(Some(mut storage)) => {
            if let Err(error) = with_public_mut!(cache => storage.synchronize_public_cache(cache)?)
            {
                super::storage_access::clear_recovery_key();
                INIT_STATE.with(|s| *s.borrow_mut() = InitState::Locked);
                return Err(error);
            }
            start(storage);
            Ok(StorageWorkerResponse::Saved)
        }
        Ok(None) => {
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Locked);
            Ok(StorageWorkerResponse::WrongPassword)
        }
        Err(e) => {
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Locked);
            Err(e)
        }
    }
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

// New operations require private access unless deliberately classified here.
fn requires_private(req: &StorageWorkerRequest) -> bool {
    use StorageWorkerRequest::*;
    match req {
        GetSetting(key) | SetSetting { key, .. } => !SqliteStorage::is_public_setting(key),
        Status
        | OpenPublic
        | Create(_)
        | Unlock(_)
        | WalletContext
        | PasskeyContext
        | UnlockWallet { .. }
        | UnlockPasskey { .. }
        | Reset
        | Pause
        | Ping
        | SyncState
        | ProcessPendingState
        | SaveEvents(_)
        | SaveSyncProgress { .. }
        | ClearIndexingCursors
        | ClampLastFullyIndexedLedger(_)
        | RecipientLookup { .. }
        | OperationalFeed { .. }
        | ListPoolGvkEvents { .. }
        | PoolHasCommitments { .. }
        | ConfigureTelemetry(_)
        | DumpLogs => false,
        _ => true,
    }
}

// Main router of worker requests
pub(crate) async fn router(req: StorageWorkerRequest) -> Result<StorageWorkerResponse> {
    if let InitState::Failed(message) = INIT_STATE.with(|s| s.borrow().clone()) {
        return Err(anyhow!(message));
    }
    if matches!(
        req,
        StorageWorkerRequest::Create(_)
            | StorageWorkerRequest::Unlock(_)
            | StorageWorkerRequest::UnlockWallet { .. }
            | StorageWorkerRequest::UnlockPasskey { .. }
            | StorageWorkerRequest::WalletContext
            | StorageWorkerRequest::PasskeyContext
    ) && INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Pending))
    {
        return Err(anyhow!("private data is opening; retry shortly"));
    }
    if requires_private(&req) && !INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Ready)) {
        return Err(anyhow!("private data is locked; unlock it first"));
    }
    let resp = match req {
        StorageWorkerRequest::OpenPublic => {
            anyhow::ensure!(
                !INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Pending)),
                "storage is opening"
            );
            if PUBLIC_STORAGE.with(|s| s.borrow().is_none()) {
                INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);
                let opened = super::storage_access::open_public().await;
                INIT_STATE.with(|s| *s.borrow_mut() = InitState::Locked);
                let storage = opened?;
                PUBLIC_STORAGE.with(|s| *s.borrow_mut() = Some(storage));
                start_processor();
                kick_processor();
            }
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::Status => match INIT_STATE.with(|s| s.borrow().clone()) {
            InitState::Pending => {
                StorageWorkerResponse::Status(crate::protocol::StorageStatus::Opening)
            }
            state => StorageWorkerResponse::Status(
                super::storage_access::status(matches!(state, InitState::Ready)).await?,
            ),
        },
        StorageWorkerRequest::Create(password) => {
            return open_with(async {
                Ok(Some(super::storage_access::create(&password.0).await?))
            })
            .await;
        }
        StorageWorkerRequest::Unlock(password) => {
            return open_with(super::storage_access::unlock(&password.0)).await;
        }
        StorageWorkerRequest::WalletContext => {
            StorageWorkerResponse::WalletContext(super::storage_access::wallet_context().await?)
        }
        StorageWorkerRequest::EnrollWallet {
            password,
            context,
            secret,
        } => {
            anyhow::ensure!(
                INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Ready)),
                "unlock the database first"
            );
            super::storage_access::enroll_wallet(&password.0, context, &secret.0)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UnlockWallet { context, secret } => {
            return open_with(super::storage_access::unlock_wallet(&context, &secret.0)).await;
        }
        StorageWorkerRequest::PasskeyContext => {
            StorageWorkerResponse::PasskeyContext(super::storage_access::passkey_context().await?)
        }
        StorageWorkerRequest::EnrollPasskey {
            password,
            context,
            secret,
        } => {
            anyhow::ensure!(
                INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Ready)),
                "unlock the database first"
            );
            super::storage_access::enroll_passkey(&password.0, context, &secret.0)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UnlockPasskey { context, secret } => {
            return open_with(super::storage_access::unlock_passkey(&context, &secret.0)).await;
        }
        StorageWorkerRequest::RemoveWallet(password) => {
            super::storage_access::remove_wallet(&password.0)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::RemovePasskey(password) => {
            super::storage_access::remove_passkey(&password.0)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::RecoverPassword(password) => {
            anyhow::ensure!(
                INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Ready)),
                "unlock the database first"
            );
            super::storage_access::recover_password(&password.0)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ChangePassword { current, new } => {
            if super::storage_access::change_password(&current.0, &new.0)? {
                StorageWorkerResponse::Saved
            } else {
                StorageWorkerResponse::WrongPassword
            }
        }
        StorageWorkerRequest::Reset => {
            anyhow::ensure!(
                !INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Pending)),
                "the database is being opened"
            );
            detach();
            super::storage_access::reset().await?;
            let cache = super::storage_access::open_public().await?;
            PUBLIC_STORAGE.with(|s| *s.borrow_mut() = Some(cache));
            start_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::Pause => {
            anyhow::ensure!(
                !INIT_STATE.with(|s| matches!(*s.borrow(), InitState::Pending)),
                "the database is being opened"
            );
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
                    InitState::Locked => {
                        anyhow::ensure!(
                            PUBLIC_STORAGE.with(|s| s.borrow().is_some()),
                            "public storage is not initialized"
                        );
                        kick_processor();
                        return Ok(StorageWorkerResponse::Pong);
                    }
                }

                TimeoutFuture::new(50).await;
            }
        }
        StorageWorkerRequest::SyncState => {
            tracing::trace!("[{WORKER_NAME}] get current sync");
            let state = with_public!(s => s.get_sync_metadata()?)?;
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
            with_public_mut!(s => s.save_events_batch(&events_data)?)?;
            if STORAGE.with(|s| s.borrow().is_some()) {
                with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            }
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
            with_public_mut!(s => s.save_sync_progress(&metadata, fully_indexed)?)?;
            if STORAGE.with(|s| s.borrow().is_some()) {
                with_storage_mut!(s => s.save_sync_progress(&metadata, fully_indexed)?)?;
            }
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClearIndexingCursors => {
            tracing::trace!("[{WORKER_NAME}] clearing indexing cursors for RPC handoff");
            with_public_mut!(s => s.clear_indexing_cursors()?)?;
            if STORAGE.with(|s| s.borrow().is_some()) {
                with_storage_mut!(s => s.clear_indexing_cursors()?)?;
            }
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClampLastFullyIndexedLedger(max_ledger) => {
            tracing::trace!("[{WORKER_NAME}] clamping last_fully_indexed_ledger to {max_ledger}");
            with_public_mut!(s => s.clamp_last_fully_indexed_ledger(max_ledger)?)?;
            if STORAGE.with(|s| s.borrow().is_some()) {
                with_storage_mut!(s => s.clamp_last_fully_indexed_ledger(max_ledger)?)?;
            }
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
            let value = if SqliteStorage::is_public_setting(&key) {
                with_public!(s => s.get_setting_json::<serde_json::Value>(&key)?)?
            } else {
                with_storage!(s => s.get_setting_json::<serde_json::Value>(&key)?)?
            };
            let value_json = value.map(|value| value.to_string());
            StorageWorkerResponse::Setting(value_json)
        }
        StorageWorkerRequest::SetSetting { key, value_json } => {
            tracing::trace!("[{WORKER_NAME}] set setting {key}");
            let value: serde_json::Value = serde_json::from_str(&value_json)?;
            if SqliteStorage::is_public_setting(&key) {
                with_public_mut!(s => s.set_setting_json(&key, &value)?)?;
            } else {
                with_storage_mut!(s => s.set_setting_json(&key, &value)?)?;
            }
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
            let lookup = with_public!(s =>
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
            let list = with_public!(s =>
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
                with_public!(s => s.list_pool_gvk_events(&pool_contract_id, after, limit)?)?;
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
            let found = with_public!(s =>
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
        // Public processing continues while locked. Private processing starts
        // only after a successful open and cache import.
        if PUBLIC_STORAGE.with(|s| s.borrow().is_none()) {
            break;
        }
        let mut did_work = with_public_mut!(storage => process_local_state_batch(storage)?)?;
        if STORAGE.with(|s| s.borrow().is_some()) {
            did_work |= with_storage_mut!(storage => process_local_state_batch(storage)?)?;
        }
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

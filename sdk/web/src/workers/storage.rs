use crate::protocol::{
    AdminASPRequest, AspSecret, CorrelatedRequest, DisclaimerStatePayload, DisclosureInputs,
    DisclosureInputsRequest, PublicEncryptionKeyPair, PublicNoteKeyPair, SessionPolicy,
    StorageWorkerRequest, StorageWorkerResponse, UserKeys,
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
        OperationalFeedItem, PortfolioBalance, RecipientLookup, Sensitive, SyncMetadata,
        UserNoteSummary,
    },
    zk::{
        crypto::asp_membership_leaf,
        encryption::{derive_encryption_and_note_keypairs, derive_membership_blinding},
        flows::TransactParams,
    },
};
use tracing::Instrument;
use wasm_bindgen::JsError;
use wasm_bindgen_futures::spawn_local;

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

#[derive(Clone, Debug)]
enum InitState {
    Pending,
    Ready,
    Failed(String),
}

#[cfg(target_arch = "wasm32")]
fn is_opfs_locked_error(message: &str) -> bool {
    message.contains("NoModificationAllowedError")
        && (message.contains("createSyncAccessHandle")
            || message.contains("Access Handles cannot be created"))
}

thread_local! {
    static STORAGE: RefCell<Option<SqliteStorage>> = const { RefCell::new(None) };
    static PROCESSOR_TX: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Pending) };
    /// The account whose wallet session the client has opened.
    ///
    /// Held in the worker isolate rather than on the main thread: document
    /// script cannot touch it directly, and the only way to change it is
    /// `BindSession`, which the raw RPC surface refuses.
    static BOUND_SESSION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Refuse an account-bound request that is not for the bound account.
///
/// A failure, not a fallback — serving whichever account is bound would answer
/// about a different account without saying so. Neither address appears in the
/// error: naming the bound one would disclose the open session to a caller that
/// guessed, and the message reaches logs.
fn ensure_session_binding(address: &str) -> Result<()> {
    let bound = BOUND_SESSION.with(|session| session.borrow().clone());
    match bound {
        Some(bound) if bound == address => Ok(()),
        Some(_) => Err(anyhow!(
            "refused: this account's data is not available to the open wallet session"
        )),
        None => Err(anyhow!(
            "refused: no wallet session is bound to this storage worker"
        )),
    }
}

/// Refuse a request that needs a bound session but names no account.
///
/// Chain-state writes are deployment-global, so any bound session authorizes
/// them; an unbound worker performs no writes at all.
fn ensure_session_present() -> Result<()> {
    let bound = BOUND_SESSION.with(|session| session.borrow().is_some());
    if bound {
        Ok(())
    } else {
        Err(anyhow!(
            "refused: no wallet session is bound to this storage worker"
        ))
    }
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

async fn init() -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    #[cfg(target_arch = "wasm32")]
    if let Err(e) = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    {
        let error_details = format!("{e:?}");
        let text = e.to_string();
        let combined = if text.is_empty() {
            error_details.clone()
        } else {
            format!("{text} {error_details}")
        };

        let msg = if is_opfs_locked_error(&combined) {
            "Another tab or window is using this app's local database. Please close other tabs/windows running this app, then reload this page.".to_string()
        } else {
            "Failed to initialize local database storage.".to_string()
        };

        tracing::error!(details = %error_details, "[{WORKER_NAME}] fatal error installing OPFS Sqlite VFS");
        INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
        return Err(JsError::new(&msg));
    }

    let storage = match SqliteStorage::connect() {
        Ok(storage) => storage,
        Err(e) => {
            // `e.to_string()` is short and SQL-free (MigrationFailedError /
            // AmbiguousKeypairsError in state/storage.rs); the full chain only
            // goes to this log via Debug, never to the modal.
            let error_details = format!("{e:?}");
            let msg = e.to_string();
            tracing::error!(details = %error_details, "[{WORKER_NAME}] fatal error opening local database");
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
    // Central session gate; request arms make no privilege decisions of their own.
    match req.session_policy() {
        SessionPolicy::SessionControl | SessionPolicy::Public => {}
        SessionPolicy::KeyMaterial(address) | SessionPolicy::BoundRead(address) => {
            ensure_session_binding(address)?;
        }
        SessionPolicy::BoundWrite { address } => match address {
            Some(address) => ensure_session_binding(address)?,
            None => ensure_session_present()?,
        },
    }
    let resp = match req {
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
        StorageWorkerRequest::PortfolioBalances(address) => {
            tracing::trace!(
                "[{WORKER_NAME}] list portfolio balances for the account {}",
                Sensitive(&address)
            );
            // Load the contract config from the embedded deployment JSON rather than
            // receiving it over the worker bridge: ContractConfig contains the
            // internally-tagged `AssetDescriptor` enum, which the bincode worker codec
            // cannot deserialize (panics with DeserializeAnyNotSupported).
            let config: ContractConfig = serde_json::from_str(crate::DEPLOYMENT)?;
            let list = with_storage!(s => s.list_portfolio_balances(&address, &config)?)?;
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
        StorageWorkerRequest::BindSession(address) => {
            tracing::debug!(
                "[{WORKER_NAME}] binding storage session to the account {}",
                Sensitive(&address)
            );
            // Last write wins, so that switching accounts rebinds rather than
            // requiring a teardown. The client sends this only after its own
            // identity checks have passed; the worker's job is to make the
            // bound account the *only* one servable, not to adjudicate which
            // account the session should be for.
            BOUND_SESSION.with(|session| *session.borrow_mut() = Some(address));
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UnbindSession => {
            tracing::debug!("[{WORKER_NAME}] releasing the bound storage session");
            // Revokes the capability and leaves the data alone. Wiping the
            // local database on disconnect is a separate, irreversible
            // product decision that is not this crate's to take.
            BOUND_SESSION.with(|session| *session.borrow_mut() = None);
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DumpLogs => {
            StorageWorkerResponse::Logs(crate::telemetry::dump_recent_logs())
        }
        StorageWorkerRequest::DiagnoseAmbiguousKeypairs { account_address } => {
            tracing::debug!(
                account = %Sensitive(&account_address),
                "[{WORKER_NAME}] building ambiguous-keypairs recovery diagnostic",
            );
            // Bypasses with_storage!/the STORAGE slot: must work precisely
            // when normal init left it empty.
            let conn = SqliteStorage::connect_raw_for_diagnostics()?;
            let diagnostic = SqliteStorage::diagnose_ambiguous_keypairs(&conn, &account_address)?;
            StorageWorkerResponse::AmbiguousKeypairsDiagnostic(diagnostic)
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected process_pending_state response: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }

    async fn clear_indexing_cursors(&self) -> Result<(), Error> {
        match self
            .call(StorageWorkerRequest::ClearIndexingCursors, 2_000)
            .await
            .map_err(|e| Error::Other(e.to_string()))?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(Error::Other(format!("unexpected response: {other:?}"))),
        }
    }

    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error> {
        match self
            .call(
                StorageWorkerRequest::ClampLastFullyIndexedLedger(max_ledger),
                2_000,
            )
            .await
            .map_err(|e| Error::Other(e.to_string()))?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(Error::Other(format!("unexpected response: {other:?}"))),
        }
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        self.ping().await.map_err(|e| Error::Other(e.to_string()))
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading spendable notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        config: &ContractConfig,
    ) -> Result<Vec<PortfolioBalance>, Error> {
        match self
            .call(
                StorageWorkerRequest::PortfolioBalances(user_address.to_string()),
                5_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::PortfolioBalances(balances)) => {
                let _ = config;
                Ok(balances)
            }
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading portfolio balances: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading user notes: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading operational feed: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response looking up recipient: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response building transact params: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response building disclosure inputs: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, Error> {
        let _ = user_address;
        Err(Error::Other(
            "full stored user keys are not available on the storage bridge; use asp_secret".into(),
        ))
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
                .ok_or_else(|| Error::Other("ASP secret not found in worker storage".into()))
                .map(|asp| asp.membership_blinding),
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading ASP secret: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
                let keys = keys
                    .ok_or_else(|| Error::Other("user keys not found in worker storage".into()))?;
                Ok((keys.note_keypair.public, keys.encryption_keypair.public))
            }
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response loading user keys: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
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
                    Error::Other(format!(
                        "recipient {address} not found in the public key registry; \
                         they must register keys on-chain"
                    ))
                })?;
                Ok((entry.note_key, entry.encryption_key))
            }
            Ok(other) => Err(Error::Other(format!(
                "unexpected storage response looking up recipient: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }
}

/// Acceptance tests for the session-binding capability guard.
///
/// Each `#[test]` runs on its own thread, so `BOUND_SESSION` starts empty in
/// every one of them and no test can observe another's binding.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod session_binding_tests {
    use super::*;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const OTHER: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    fn bind(address: &str) {
        futures::executor::block_on(router(StorageWorkerRequest::BindSession(
            address.to_string(),
        )))
        .expect("binding a session succeeds");
    }

    fn unbind() {
        futures::executor::block_on(router(StorageWorkerRequest::UnbindSession))
            .expect("releasing a session succeeds");
    }

    fn route(req: StorageWorkerRequest) -> anyhow::Result<StorageWorkerResponse> {
        futures::executor::block_on(router(req))
    }

    fn route_labeled(req: StorageWorkerRequest) -> (String, anyhow::Result<StorageWorkerResponse>) {
        let label = format!("{req:?}");
        (label, route(req))
    }

    fn is_session_refusal(result: &anyhow::Result<StorageWorkerResponse>) -> bool {
        result
            .as_ref()
            .expect_err("expected a refusal")
            .to_string()
            .contains("wallet session")
    }

    fn passed_gate(result: anyhow::Result<StorageWorkerResponse>) -> bool {
        match result {
            Ok(_) => true,
            Err(e) => e.to_string().contains("storage is not initialized"),
        }
    }

    fn accept_disclaimer(address: &str) -> StorageWorkerRequest {
        StorageWorkerRequest::AcceptDisclaimer(address.to_string(), "hash".to_string())
    }

    fn record_operation(address: &str) -> StorageWorkerRequest {
        StorageWorkerRequest::RecordOperation {
            address: address.to_string(),
            pool_contract_id: "CPOOL".to_string(),
            op_type: "deposit".to_string(),
            amount: "1".to_string(),
            direction: "in".to_string(),
            counterparty: None,
            tx_hash: None,
        }
    }

    fn chain_state_writes() -> Vec<StorageWorkerRequest> {
        vec![
            StorageWorkerRequest::SaveEvents(ContractsEventData {
                events: Vec::new(),
                cursor: String::new(),
                latest_ledger: 0,
            }),
            StorageWorkerRequest::SaveSyncProgress {
                metadata: Vec::new(),
                fully_indexed: false,
            },
            StorageWorkerRequest::ClearIndexingCursors,
            StorageWorkerRequest::ClampLastFullyIndexedLedger(0),
            StorageWorkerRequest::ProcessPendingState,
        ]
    }

    fn account_data_reads(address: &str) -> Vec<StorageWorkerRequest> {
        vec![
            StorageWorkerRequest::UserNotes(address.to_string(), 10),
            StorageWorkerRequest::PortfolioBalances(address.to_string()),
            StorageWorkerRequest::ListOperations {
                address: address.to_string(),
                pool_contract_id: "CPOOL".to_string(),
                limit: 10,
            },
            StorageWorkerRequest::UnspentUserNotes {
                user_address: address.to_string(),
                pool_contract_id: "CPOOL".to_string(),
            },
            StorageWorkerRequest::PoolUserNotes {
                user_address: address.to_string(),
                pool_contract_id: "CPOOL".to_string(),
            },
        ]
    }

    #[test]
    fn account_record_writes_require_a_bound_session() {
        assert!(
            is_session_refusal(&route(accept_disclaimer(OWNER))),
            "AcceptDisclaimer must be refused before any session exists"
        );
        assert!(
            is_session_refusal(&route(record_operation(OWNER))),
            "RecordOperation must be refused before any session exists"
        );
    }

    #[test]
    fn account_record_writes_reject_a_cross_account_address() {
        bind(OWNER);
        for req in [accept_disclaimer(OTHER), record_operation(OTHER)] {
            let result = route(req);
            assert!(
                is_session_refusal(&result),
                "cross-account write served: {result:?}"
            );
            let message = result.expect_err("refusal").to_string();
            assert!(
                !message.contains(OWNER) && !message.contains(OTHER),
                "a refusal must not disclose either address: {message}"
            );
        }
    }

    #[test]
    fn account_record_writes_serve_the_bound_account() {
        bind(OWNER);
        assert!(
            passed_gate(route(accept_disclaimer(OWNER))),
            "the bound account's disclaimer write must pass the session gate"
        );
        assert!(
            passed_gate(route(record_operation(OWNER))),
            "the bound account's operation write must pass the session gate"
        );
    }

    #[test]
    fn chain_state_writes_require_a_bound_session() {
        for req in chain_state_writes() {
            let (label, result) = route_labeled(req);
            assert!(
                is_session_refusal(&result),
                "chain-state write served without a session: {label}"
            );
        }
        bind(OWNER);
        for req in chain_state_writes() {
            let (label, result) = route_labeled(req);
            assert!(
                passed_gate(result),
                "chain-state write refused despite a bound session: {label}"
            );
        }
    }

    #[test]
    fn account_data_reads_require_the_bound_account() {
        for req in account_data_reads(OWNER) {
            let (label, result) = route_labeled(req);
            assert!(
                is_session_refusal(&result),
                "account data read served without a session: {label}"
            );
        }
        bind(OWNER);
        for req in account_data_reads(OTHER) {
            let (label, result) = route_labeled(req);
            assert!(
                is_session_refusal(&result),
                "cross-account read served: {label}"
            );
        }
        for req in account_data_reads(OWNER) {
            let (label, result) = route_labeled(req);
            assert!(
                passed_gate(result),
                "the bound account's read must pass the session gate: {label}"
            );
        }
    }

    #[test]
    fn documented_public_exceptions_reach_their_handlers_without_a_session() {
        let public_requests = vec![
            StorageWorkerRequest::DisclaimerState(OWNER.to_string()),
            StorageWorkerRequest::UserKeys(OWNER.to_string()),
            StorageWorkerRequest::GetSetting("explorer".to_string()),
            StorageWorkerRequest::SetSetting {
                key: "explorer".to_string(),
                value_json: "{}".to_string(),
            },
            StorageWorkerRequest::SyncState,
            StorageWorkerRequest::RecipientLookup {
                address: OTHER.to_string(),
                public_key_registry_contract_id: "CREG".to_string(),
            },
        ];
        for req in public_requests {
            let (label, result) = route_labeled(req);
            assert!(
                passed_gate(result),
                "documented public exception refused by the session gate: {label}"
            );
        }
    }

    #[test]
    fn unbinding_revokes_bound_write_and_read_access() {
        bind(OWNER);
        assert!(passed_gate(route(accept_disclaimer(OWNER))));
        unbind();
        assert!(is_session_refusal(&route(accept_disclaimer(OWNER))));
        for req in account_data_reads(OWNER) {
            let (label, result) = route_labeled(req);
            assert!(
                is_session_refusal(&result),
                "read still served after unbind: {label}"
            );
        }
        for req in chain_state_writes() {
            let (label, result) = route_labeled(req);
            assert!(
                is_session_refusal(&result),
                "chain-state write still served after unbind: {label}"
            );
        }
    }

    #[test]
    fn nothing_is_served_before_a_session_is_bound() {
        let err = ensure_session_binding(OWNER).expect_err("no session is bound yet");
        assert!(
            err.to_string().contains("no wallet session is bound"),
            "the refusal must say the worker has no session, not that the              account is wrong: {err}"
        );
    }

    #[test]
    fn the_bound_account_is_served() {
        bind(OWNER);
        assert!(ensure_session_binding(OWNER).is_ok());
    }

    #[test]
    fn another_account_is_refused_while_one_is_bound() {
        bind(OWNER);
        let err = ensure_session_binding(OTHER).expect_err("only the bound account is servable");
        assert!(
            !err.to_string().contains(OWNER) && !err.to_string().contains(OTHER),
            "a refusal must not disclose either address: {err}"
        );
    }

    #[test]
    fn the_comparison_is_exact() {
        // Guards against a later "helpful" relaxation to trimmed, prefix or
        // case-insensitive matching. Strkeys are exact, and a near-match here
        // would serve one account's key material to another.
        bind(OWNER);
        assert!(ensure_session_binding(&OWNER.to_ascii_lowercase()).is_err());
        assert!(ensure_session_binding(&format!(" {OWNER}")).is_err());
        assert!(ensure_session_binding(&OWNER[..OWNER.len() - 1]).is_err());
        assert!(ensure_session_binding("").is_err());
    }

    #[test]
    fn rebinding_moves_the_capability_rather_than_widening_it() {
        // Account switching must not accumulate servable accounts.
        bind(OWNER);
        bind(OTHER);
        assert!(ensure_session_binding(OTHER).is_ok());
        assert!(
            ensure_session_binding(OWNER).is_err(),
            "the previously bound account must stop being servable"
        );
    }

    #[test]
    fn releasing_revokes_the_capability() {
        bind(OWNER);
        unbind();
        assert!(ensure_session_binding(OWNER).is_err());
    }

    #[test]
    fn the_asp_secret_read_is_gated_before_storage_is_touched() {
        // Proves the guard is wired into the router ahead of the database
        // access, not merely available as a free function. Storage is not
        // initialized in this test process, so reaching it would produce
        // "storage is not initialized" instead.
        let err =
            futures::executor::block_on(router(StorageWorkerRequest::AspSecret(OWNER.to_string())))
                .expect_err("an unbound ASP secret read is refused");
        assert!(
            err.to_string().contains("no wallet session is bound"),
            "the read must be refused by the session guard, not by storage: {err}"
        );
    }

    #[test]
    fn the_disclosure_input_build_is_gated() {
        // DisclosureInputs returns note_private_key and note_blinding, so an
        // ungated build discloses strictly more than the ASP secret read does.
        //
        // Transact is gated by the identical one-line call on its own arm and
        // is not stubbed here: TransactRequest has eighteen fields, several of
        // them prover types, and the stub would be more fixture than test.
        // Its classification is covered in protocol.rs.
        let err = futures::executor::block_on(router(StorageWorkerRequest::DisclosureInputs(
            DisclosureInputsRequest {
                user_address: OWNER.to_string(),
                pool_address: "CPOOL".to_string(),
                selected_commitments: Vec::new(),
                pool_root: None,
                pool_next_index: 0,
                tree_depth: 20,
            },
        )))
        .expect_err("an unbound disclosure input build is refused");
        assert!(
            err.to_string().contains("no wallet session is bound"),
            "the build must be refused by the session guard, not by storage: {err}"
        );
    }

    #[test]
    fn the_key_write_is_gated_before_any_derivation() {
        // Same reasoning for the write path: a refusal must cost no key
        // material derived from a signature that is about to be rejected.
        let err = futures::executor::block_on(router(StorageWorkerRequest::DeriveSaveUserKeys(
            OWNER.to_string(),
            stellar_private_payments::types::KeyDerivationSignature(vec![0u8; 64]),
            "Test Network".to_string(),
        )))
        .expect_err("an unbound key write is refused");
        assert!(
            err.to_string().contains("no wallet session is bound"),
            "the write must be refused by the session guard: {err}"
        );
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

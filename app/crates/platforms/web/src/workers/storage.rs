use crate::protocol::{
    AdminASPRequest, AspSecret, DisclaimerStatePayload, DisclosureInputs, DisclosureNoteInputs,
    PublicEncryptionKeyPair, PublicNoteKeyPair, StorageWorkerRequest, StorageWorkerResponse,
    UserKeys,
};
use anyhow::{Result, anyhow};
use futures::{FutureExt, channel::mpsc, stream::StreamExt};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use std::cell::RefCell;
use stellar_private_payments_sdk::{
    BuildTransactParams, PoolError, SpendableNote, Storage, TransactRequest, build_transact_params,
    build_validated_pool_tree,
    chain::ContractDataStorage,
    load_user_key_material,
    state::{SqliteStorage, StoredUserKeys, process_local_state_batch},
    tx::{
        crypto::asp_membership_leaf,
        encryption::{derive_encryption_and_note_keypairs, derive_membership_blinding},
        flows::TransactParams,
    },
    types::{
        ContractConfig, ContractsEventData, EncryptionPublicKey, NotePublicKey, SyncMetadata,
        UserNoteSummary,
    },
};
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
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    log::debug!("[{WORKER_NAME}] starting...");
    StorageWorker::registrar().register();
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[{WORKER_NAME}] init failed: {e:?}");
        }
    });
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
        let debug = format!("{e:?}");
        let text = e.to_string();
        let combined = if text.is_empty() {
            debug.clone()
        } else {
            format!("{text} {debug}")
        };

        let msg = if is_opfs_locked_error(&combined) {
            "Another tab or window is using this app's local database. Please close other tabs/windows running this app, then reload this page.".to_string()
        } else {
            "Failed to initialize local database storage.".to_string()
        };

        log::error!("[{WORKER_NAME}] fatal error installing OPFS Sqlite VFS: {debug}");
        INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
        return Err(JsError::new(&msg));
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
    log::debug!("[{WORKER_NAME}] initialized");

    Ok(())
}

#[oneshot]
pub(crate) async fn StorageWorker(req: StorageWorkerRequest) -> StorageWorkerResponse {
    match router(req).await {
        Ok(r) => r,
        Err(e) => StorageWorkerResponse::Error(e.to_string()),
    }
}

// Main router of worker requests
pub(crate) async fn router(req: StorageWorkerRequest) -> Result<StorageWorkerResponse> {
    let resp = match req {
        StorageWorkerRequest::Ping => {
            log::trace!("[{WORKER_NAME}] ping");
            loop {
                let state = INIT_STATE.with(|s| s.borrow().clone());
                match state {
                    InitState::Ready => {
                        log::trace!("[{WORKER_NAME}] pong");
                        kick_processor();
                        return Ok(StorageWorkerResponse::Pong);
                    }
                    InitState::Failed(msg) => {
                        log::debug!("[{WORKER_NAME}] ping -> init failed");
                        return Ok(StorageWorkerResponse::Error(msg));
                    }
                    InitState::Pending => {}
                }

                TimeoutFuture::new(50).await;
            }
        }
        StorageWorkerRequest::SyncState => {
            log::trace!("[{WORKER_NAME}] get current sync");
            let state = with_storage!(s => s.get_sync_metadata()?)?;
            let resp = StorageWorkerResponse::SyncState(state);
            log::trace!("[{WORKER_NAME}] sending current sync");
            resp
        }
        StorageWorkerRequest::SaveEvents(events_data) => {
            log::trace!(
                "[{WORKER_NAME}] saving {} raw contract events",
                events_data.events.len()
            );
            with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            log::trace!(
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
            log::trace!(
                "[{WORKER_NAME}] saving bulk sync progress for {} contracts (fully_indexed={fully_indexed})",
                metadata.len()
            );
            with_storage_mut!(s => s.save_sync_progress(&metadata, fully_indexed)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClearIndexingCursors => {
            log::trace!("[{WORKER_NAME}] clearing indexing cursors for RPC handoff");
            with_storage_mut!(s => s.clear_indexing_cursors()?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DeriveSaveUserKeys(address, signature, network_context) => {
            log::trace!("[{WORKER_NAME}] deriving and saving user keys for the account {address}");
            let (note_keypair, encryption_keypair) =
                derive_encryption_and_note_keypairs(signature.clone())?;
            let membership_blinding = derive_membership_blinding(&signature, &network_context)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair, &membership_blinding)?)?;
            log::trace!(
                "[{WORKER_NAME}] saved notes, encryption keys, and ASP secret for the account {address}"
            );
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DisclaimerState(address) => {
            log::trace!("[{WORKER_NAME}] disclaimer state for account {address}");
            let state = with_storage_mut!(s => s.get_disclaimer_state(&address)?)?;
            StorageWorkerResponse::DisclaimerState(DisclaimerStatePayload {
                disclaimer_text_md: state.disclaimer_text_md,
                disclaimer_hash_hex: state.disclaimer_hash_hex,
                accepted: state.accepted,
            })
        }
        StorageWorkerRequest::AcceptDisclaimer(address, disclaimer_hash_hex) => {
            log::trace!("[{WORKER_NAME}] accept disclaimer for account {address}");
            with_storage_mut!(s => s.accept_current_disclaimer(&address, &disclaimer_hash_hex)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::GetSetting(key) => {
            log::trace!("[{WORKER_NAME}] fetch setting {key}");
            let value_json = with_storage!(s => s.get_setting_json::<serde_json::Value>(&key)?)?
                .map(|value| value.to_string());
            StorageWorkerResponse::Setting(value_json)
        }
        StorageWorkerRequest::SetSetting { key, value_json } => {
            log::trace!("[{WORKER_NAME}] set setting {key}");
            let value: serde_json::Value = serde_json::from_str(&value_json)?;
            with_storage_mut!(s => s.set_setting_json(&key, &value)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UserKeys(address) => {
            log::trace!("[{WORKER_NAME}] fetch user keys for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            if opt.is_some() {
                log::trace!(
                    "[{WORKER_NAME}] fetched notes and encryption keys for the account {address}"
                );
            } else {
                log::trace!(
                    "[{WORKER_NAME}] not found notes and encryption keys for the account {address}"
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
            log::trace!("[{WORKER_NAME}] fetch ASP secret for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            StorageWorkerResponse::AspSecret(opt.map(|keys| AspSecret {
                membership_blinding: keys.membership_blinding,
            }))
        }
        StorageWorkerRequest::UserNotes { address, offset, limit } => {
            log::trace!("[{WORKER_NAME}] list user notes for the account {address} (offset={offset}, limit={limit})");
            let list = with_storage!(s => s.list_user_notes(&address, offset, limit)?)?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} notes for the account {address}",
                list.len()
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::CountUserNotes(address) => {
            log::trace!("[{WORKER_NAME}] count user notes for the account {address}");
            let count = with_storage!(s => s.count_user_notes(&address)?)?;
            log::trace!("[{WORKER_NAME}] total notes for {address}: {count}");
            StorageWorkerResponse::UserNotesCount(count)
        }
        StorageWorkerRequest::PortfolioBalances(address) => {
            log::trace!("[{WORKER_NAME}] list portfolio balances for the account {address}");
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
            log::trace!(
                "[{WORKER_NAME}] list all unspent notes for the account {user_address} in pool {pool_contract_id}"
            );
            let list = with_storage!(s =>
                s.list_unspent_user_notes(&pool_contract_id, &user_address)?
            )?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} unspent notes for the account {user_address}",
                list.len()
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::PoolUserNotes {
            user_address,
            pool_contract_id,
        } => {
            log::trace!(
                "[{WORKER_NAME}] list all notes for the account {user_address} in pool {pool_contract_id}"
            );
            let list = with_storage!(s =>
                s.list_pool_user_notes(&pool_contract_id, &user_address)?
            )?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} notes for the account {user_address}",
                list.len()
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::RecentPubKeys(limit) => {
            log::trace!("[{WORKER_NAME}] fetch pub keys for the address book");
            let list = with_storage!(s => s.get_recent_public_keys(limit)?)?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} pub keys for the address book",
                list.len()
            );
            StorageWorkerResponse::PubKeys(list)
        }
        StorageWorkerRequest::RecipientLookup {
            address,
            public_key_registry_contract_id,
        } => {
            log::trace!("[{WORKER_NAME}] lookup public keys for {address}");
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
            log::trace!("[{WORKER_NAME}] fetch operational feed");
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
            log::trace!(
                "[{WORKER_NAME}] build selective disclosure inputs for {}",
                req.user_address
            );

            if req.selected_commitments.is_empty() || req.selected_commitments.len() > 4 {
                return Ok(StorageWorkerResponse::Error(
                    "selective disclosure requires 1..=4 selected commitments".to_string(),
                ));
            }

            let pool_root = req
                .pool_root
                .ok_or_else(|| anyhow::anyhow!("missing pool_root"))?;
            let (note_privkey, _note_pubkey, _encryption_pubkey, _membership_blinding) = STORAGE
                .with(|s| {
                    let borrow = s.borrow();
                    let storage = borrow
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;
                    load_user_key_material(storage, &req.user_address)
                })?;

            let tree = match STORAGE.with(|s| {
                let borrow = s.borrow();
                let storage = borrow
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;
                build_validated_pool_tree(
                    storage,
                    &req.pool_address,
                    req.pool_next_index,
                    req.tree_depth,
                    pool_root,
                )
            })? {
                Ok(tree) => tree,
                Err(status) => return Ok(StorageWorkerResponse::AspMembershipSync(status)),
            };

            let mut notes = Vec::with_capacity(req.selected_commitments.len());
            for commitment in &req.selected_commitments {
                let (amount, blinding, leaf_index) = with_storage!(
                    s => s.get_unspent_user_note_by_commitment(&req.pool_address, &req.user_address, commitment)?
                )?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unspent note not found for commitment {} in pool {} \
                         (note may be spent, not owned, or belong to a different pool)",
                        commitment,
                        req.pool_address
                    )
                })?;

                let proof = tree.proof(leaf_index)?;

                notes.push(DisclosureNoteInputs {
                    root: proof.root,
                    note_commitment: *commitment,
                    note_amount: amount,
                    note_private_key: note_privkey.clone(),
                    note_blinding: blinding,
                    merkle_path_indices: proof.path_indices,
                    merkle_path_elements: proof.path_elements,
                });
            }

            StorageWorkerResponse::DisclosureInputs(DisclosureInputs { notes })
        }
        StorageWorkerRequest::DeriveASPleaf(AdminASPRequest {
            membership_blinding,
            pubkey,
        }) => {
            log::trace!("[{WORKER_NAME}] derive user leaf from the pubkey for the admin");
            let user_leaf = asp_membership_leaf(&pubkey, &membership_blinding)?;
            log::trace!("[{WORKER_NAME}] derived user leaf from the pubkey for the admin");
            StorageWorkerResponse::DeriveASPleaf(user_leaf)
        }
        StorageWorkerRequest::Transact(req) => {
            log::trace!("[{WORKER_NAME}] transact");
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
            log::error!("[{WORKER_NAME}] events processing failed: {e:#}");
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

    /// Send a request to the storage worker and return its response.
    ///
    /// Worker-level [`StorageWorkerResponse::Error`] is mapped to `Err`.
    pub(crate) async fn call(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> anyhow::Result<StorageWorkerResponse> {
        let mut bridge = self.bridge.fork();
        let fut = bridge.run(req).fuse();
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
        match self.call(StorageWorkerRequest::Ping, 5_000).await? {
            StorageWorkerResponse::Pong => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }

    pub(crate) async fn clear_indexing_cursors(&self) -> anyhow::Result<()> {
        match self
            .call(StorageWorkerRequest::ClearIndexingCursors, 2_000)
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }

    pub(crate) async fn stored_bootnode_url(&self) -> Option<String> {
        match self
            .call(
                StorageWorkerRequest::GetSetting(
                    stellar_private_payments_sdk::state::APP_SETTING_BOOTNODE_CONFIG.to_string(),
                ),
                2_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::Setting(Some(json))) => {
                serde_json::from_str::<stellar_private_payments_sdk::types::BootnodeSetting>(&json)
                    .ok()
                    .filter(|config| config.enabled && !config.url.is_empty())
                    .map(|config| config.url)
            }
            _ => None,
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
    fn fork(&self) -> Result<Self, PoolError> {
        Ok(Self {
            bridge: self.bridge.fork(),
        })
    }

    async fn process_pending_state(&self) -> Result<(), PoolError> {
        // Ingest already kicks `kick_processor()` on SaveEvents; processing runs
        // in the worker background loop without blocking this bridge.
        Ok(())
    }

    async fn ensure_ready(&self) -> Result<(), PoolError> {
        self.ping()
            .await
            .map_err(|e| PoolError::Other(e.to_string()))
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError> {
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
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected storage response loading spendable notes: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, PoolError> {
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
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected storage response loading notes: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError> {
        match self
            .call(StorageWorkerRequest::Transact(req.clone()), 5_000)
            .await
        {
            Ok(StorageWorkerResponse::TransactParams(params)) => Ok(params),
            Ok(StorageWorkerResponse::AspMembershipSync(status)) => {
                Err(PoolError::MembershipSync(status))
            }
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected storage response building transact params: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn build_disclosure_inputs(
        &self,
        req: &stellar_private_payments_sdk::DisclosureInputsRequest,
    ) -> Result<stellar_private_payments_sdk::DisclosureInputs, PoolError> {
        let local_req = crate::protocol::DisclosureInputsRequest {
            user_address: req.user_address.clone(),
            pool_address: req.pool_address.clone(),
            selected_commitments: vec![req.selected_commitment],
            pool_root: req.pool_root,
            pool_next_index: req.pool_next_index,
            tree_depth: req.tree_depth,
        };
        match self
            .call(StorageWorkerRequest::DisclosureInputs(local_req), 5_000)
            .await
        {
            Ok(StorageWorkerResponse::DisclosureInputs(inputs)) => {
                let note = inputs.notes.into_iter().next().ok_or_else(|| {
                    PoolError::Other("disclosure inputs returned no notes".into())
                })?;
                Ok(stellar_private_payments_sdk::DisclosureInputs {
                    root: note.root,
                    note_commitment: note.note_commitment,
                    note_amount: note.note_amount,
                    note_private_key: note.note_private_key,
                    note_blinding: note.note_blinding,
                    merkle_path_indices: note.merkle_path_indices,
                    merkle_path_elements: note.merkle_path_elements,
                })
            }
            Ok(StorageWorkerResponse::AspMembershipSync(status)) => {
                Err(PoolError::MembershipSync(status))
            }
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected storage response building disclosure inputs: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError> {
        let _ = user_address;
        Err(PoolError::Other(
            "full user keys are not available on the storage bridge; use user_public_keys".into(),
        ))
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        match self
            .call(
                StorageWorkerRequest::UserKeys(user_address.to_string()),
                1_000,
            )
            .await
        {
            Ok(StorageWorkerResponse::UserKeys(keys)) => {
                let keys = keys.ok_or_else(|| {
                    PoolError::Other("user keys not found in worker storage".into())
                })?;
                Ok((keys.note_keypair.public, keys.encryption_keypair.public))
            }
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected storage response loading user keys: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, PoolError> {
        Ok(self.user_public_keys(user_address).await?.0)
    }
}

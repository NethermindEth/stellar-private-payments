use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;
use stellar::{Indexer, RpcError, TxConfirmStatus, confirm_tx as rpc_confirm_tx};
use types::ContractConfig;

use crate::{Error, Handle, Storage, chain::RpcClient, sleep::sleep, types::TransactionResult};

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;
const BACKGROUND_SYNC_INTERVAL_MS: u32 = 5_000;
const BOOTNODE_CATCH_UP_MAX_FAILURES: u32 = 10;
/// Bootnode JSON-RPC code: historical range complete, continue on the main
/// RPC.
const RETENTION_HANDOFF_CODE: i64 = -32_002;

const SYNC_MODE_INLINE: u8 = 0;
const SYNC_MODE_BACKGROUND: u8 = 1;

/// How the pool keeps local storage in sync with on-chain contract events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// [`crate::Client::sync`] / [`crate::Account::sync`] (and pool reads and
    /// mutations via `ensure_synced`) run deployment catch-up inline.
    Inline,
    /// Storage is kept in sync by a background task started via
    /// [`crate::Client::background_sync`]. `ensure_synced` kicks that task
    /// instead of awaiting catch-up.
    Background,
}

impl SyncMode {
    fn from_u8(value: u8) -> Self {
        match value {
            SYNC_MODE_BACKGROUND => Self::Background,
            _ => Self::Inline,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Inline => SYNC_MODE_INLINE,
            Self::Background => SYNC_MODE_BACKGROUND,
        }
    }
}

/// Shared sync handle: optional historical-sync bootnode, plus a wake / mode
/// handle for Client / Account / Pool.
#[derive(Clone)]
pub struct SyncHandle {
    bootnode_url: Option<String>,
    pub(crate) kick: Handle<SyncKick>,
}

impl SyncHandle {
    pub fn inline(bootnode_url: Option<String>) -> Self {
        Self {
            bootnode_url,
            kick: SyncKick::new(SyncMode::Inline),
        }
    }

    /// Shared sync mode (visible to all clones after [`Self::set_mode`]).
    pub fn mode(&self) -> SyncMode {
        self.kick.mode()
    }

    /// Update sync mode for this handle and every clone that shares it.
    pub fn set_mode(&self, mode: SyncMode) {
        self.kick.set_mode(mode);
    }

    /// Wake [`BackgroundSync::run`]'s idle wait early (no-op if nothing is
    /// waiting; coalesces with an in-flight round).
    pub fn kick(&self) {
        self.kick.kick();
    }

    pub fn bootnode_url(&self) -> Option<&str> {
        self.bootnode_url.as_deref()
    }

    /// Inline catch-up, or kick the background indexer, depending on mode.
    pub(crate) async fn ensure_synced<S: Storage>(
        &self,
        rpc: &RpcClient,
        storage: &S,
        contract_config: &ContractConfig,
    ) -> Result<(), Error> {
        match self.mode() {
            SyncMode::Inline => catch_up(rpc, storage, contract_config, self.bootnode_url()).await,
            SyncMode::Background => {
                self.kick();
                Ok(())
            }
        }
    }
}

/// Shared sync coordination: mode flag + wake for background idle waits.
pub(crate) struct SyncKick {
    mode: AtomicU8,
    waker: AtomicWaker,
    signaled: AtomicBool,
}

impl SyncKick {
    pub(crate) fn new(mode: SyncMode) -> Handle<Self> {
        Handle::new(Self {
            mode: AtomicU8::new(mode.as_u8()),
            waker: AtomicWaker::new(),
            signaled: AtomicBool::new(false),
        })
    }

    fn mode(&self) -> SyncMode {
        SyncMode::from_u8(self.mode.load(Ordering::Acquire))
    }

    fn set_mode(&self, mode: SyncMode) {
        self.mode.store(mode.as_u8(), Ordering::Release);
    }

    /// Request an early sync pass. Coalesces with in-flight rounds.
    pub(crate) fn kick(&self) {
        self.signaled.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    /// Wait until [`Self::kick`] or `timeout_ms`, then clear the kick flag.
    pub async fn wait_timeout(&self, timeout_ms: u32) {
        {
            let timeout = sleep(timeout_ms);
            futures::pin_mut!(timeout);
            let wait = KickWait { kick: self };
            futures::future::select(wait, timeout).await;
        }
        self.signaled.store(false, Ordering::SeqCst);
    }
}

/// Future that completes when [`SyncKick::kick`] has been called.
struct KickWait<'a> {
    kick: &'a SyncKick,
}

impl Future for KickWait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.kick.signaled.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        self.kick.waker.register(cx.waker());
        if self.kick.signaled.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Stop signal for a [`BackgroundSync`] task: sets a flag and wakes the idle
/// wait so the loop can exit promptly.
#[derive(Clone)]
pub struct BackgroundSyncStop {
    stop: Arc<AtomicBool>,
    kick: Handle<SyncKick>,
}

impl BackgroundSyncStop {
    /// Request the background loop to exit after the current round / wait.
    pub fn request(&self) {
        self.stop.store(true, Ordering::Release);
        self.kick.kick();
    }
}

/// Owned contract-event indexer task. Built from
/// [`crate::Client::background_sync`]; call [`Self::run`] on your runtime (does
/// not spawn).
#[must_use = "call/spawn BackgroundSync::run to keep the client up-to-date"]
pub struct BackgroundSync<S: Storage> {
    rpc: RpcClient,
    storage: S,
    contract_config: ContractConfig,
    bootnode_url: Option<String>,
    kick: Handle<SyncKick>,
    stop: Arc<AtomicBool>,
}

impl<S: Storage> BackgroundSync<S> {
    pub(crate) fn new(
        rpc: RpcClient,
        storage: S,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
        kick: Handle<SyncKick>,
    ) -> Self {
        Self {
            rpc,
            storage,
            contract_config,
            bootnode_url,
            kick,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cloneable handle to stop this task (also wakes the idle wait).
    pub fn stop_handle(&self) -> BackgroundSyncStop {
        BackgroundSyncStop {
            stop: Arc::clone(&self.stop),
            kick: self.kick.clone(),
        }
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Long-running indexer loop. Polls until stopped or the future is dropped.
    ///
    /// Between rounds, waits up to [`BACKGROUND_SYNC_INTERVAL_MS`] or until
    /// [`SyncKick::kick`].
    ///
    /// On a main RPC retention gap, syncs historical events via the optional
    /// bootnode until handoff, then resumes on the main RPC.
    pub async fn run(self) -> Result<(), Error> {
        if self.is_stopped() {
            return Ok(());
        }

        log::info!(
            "background sync starting (bootnode={})",
            self.bootnode_url.as_deref().unwrap_or("<none>")
        );

        let indexer = match Indexer::init(
            self.rpc.clone(),
            self.storage.fork()?,
            &self.contract_config,
        )
        .await
        {
            Ok(indexer) => {
                log::info!("background sync: main RPC indexer ready");
                indexer
            }
            Err(e) if is_rpc_sync_gap(&e) => {
                if self.is_stopped() {
                    return Ok(());
                }
                log::warn!("background sync: main RPC sync gap, switching to bootnode");
                match self.bootnode_catch_up().await {
                    Ok(()) => {}
                    Err(_) if self.is_stopped() => {
                        log::info!("background sync stopped during bootnode catch-up");
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
                if self.is_stopped() {
                    return Ok(());
                }
                log::info!("background sync: bootnode catch-up finished, resuming main RPC");
                Indexer::init(
                    self.rpc.clone(),
                    self.storage.fork()?,
                    &self.contract_config,
                )
                .await
                .map_err(|e| Error::Other(format!("indexer: {e:#}")))?
            }
            Err(e) => return Err(Error::Other(format!("indexer: {e:#}"))),
        };

        loop {
            if self.is_stopped() {
                log::info!("background sync stopped");
                return Ok(());
            }
            if let Err(e) = indexer.fetch_contract_events().await {
                log::error!("background sync fetch failed: {e:#}");
            } else if let Err(e) = self.storage.process_pending_state().await {
                log::error!("background sync process_pending_state failed: {e}");
            }
            self.kick.wait_timeout(BACKGROUND_SYNC_INTERVAL_MS).await;
        }
    }

    /// Sync historical range via bootnode until retention handoff, then clear
    /// cursors for main RPC resume.
    async fn bootnode_catch_up(&self) -> Result<(), Error> {
        bootnode_catch_up(
            &self.storage,
            &self.contract_config,
            self.bootnode_url.as_deref(),
            Some(&self.stop),
        )
        .await
    }
}

fn is_retention_handoff(err: &RpcError) -> bool {
    matches!(
        err,
        RpcError::JsonRpc {
            code: RETENTION_HANDOFF_CODE,
            ..
        }
    )
}

fn is_rpc_sync_gap(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RpcError>(),
        Some(RpcError::RpcSyncGap(_))
    )
}

/// Probe whether the main RPC needs a historical-sync bootnode.
///
/// Returns `true` on an RPC retention gap, `false` when the RPC can serve
/// history. Other indexer init errors are returned as [`Err`].
pub async fn bootnode_required<S: Storage>(
    rpc: &RpcClient,
    storage: &S,
    contract_config: &ContractConfig,
) -> Result<bool, Error> {
    match Indexer::init(rpc.clone(), storage.fork()?, contract_config).await {
        Ok(_) => Ok(false),
        Err(e) if is_rpc_sync_gap(&e) => Ok(true),
        Err(e) => Err(Error::Other(format!("bootnode probe: {e:#}"))),
    }
}

fn is_retention_handoff_err(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RpcError>(),
        Some(rpc_err) if is_retention_handoff(rpc_err)
    )
}

/// Sync historical range via bootnode until retention handoff, then clear
/// cursors for main RPC resume.
async fn bootnode_catch_up<S: Storage>(
    storage: &S,
    contract_config: &ContractConfig,
    bootnode_url: Option<&str>,
    stop: Option<&AtomicBool>,
) -> Result<(), Error> {
    let Some(bootnode) = bootnode_url else {
        return Err(Error::Other(
            "RPC sync gap: main RPC lacks history; configure a bootnode \
             or use a different RPC / fresher deployment"
                .to_string(),
        ));
    };

    log::info!("main RPC sync gap, trying bootnode at {bootnode}");
    storage.clear_indexing_cursors().await?;

    let bootnode_client =
        RpcClient::new(bootnode).map_err(|e| Error::Other(format!("bootnode rpc: {e:#}")))?;

    let bootnode_indexer =
        match Indexer::init(bootnode_client, storage.fork()?, contract_config).await {
            Ok(indexer) => indexer,
            Err(e) if is_retention_handoff_err(&e) => {
                log::info!("bootnode handoff, resuming on main RPC");
                return Ok(());
            }
            Err(e) => return Err(Error::Other(format!("bootnode indexer: {e:#}"))),
        };

    let mut consecutive_failures = 0u32;
    loop {
        if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
            return Err(Error::Other("background sync stopped".into()));
        }
        match bootnode_indexer.fetch_contract_events().await {
            // bootnode success fetch
            Ok(_) => {
                consecutive_failures = 0;
                if let Err(e) = storage.process_pending_state().await {
                    log::error!("bootnode sync process_pending_state failed: {e}");
                }
            }
            // bootnode handoff, use main RPC
            Err(e)
                if e.downcast_ref::<RpcError>()
                    .is_some_and(is_retention_handoff) =>
            {
                log::info!("bootnode handoff, resuming on main RPC");
                storage.clear_indexing_cursors().await?;
                return Ok(());
            }
            // bootnode generic error
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                log::error!(
                    "bootnode sync round failed ({consecutive_failures}/{BOOTNODE_CATCH_UP_MAX_FAILURES}): {e:#}"
                );
                if consecutive_failures >= BOOTNODE_CATCH_UP_MAX_FAILURES {
                    return Err(Error::Other(format!(
                        "bootnode sync failed after {BOOTNODE_CATCH_UP_MAX_FAILURES} consecutive errors: {e:#}"
                    )));
                }
            }
        }
        sleep(BACKGROUND_SYNC_INTERVAL_MS).await;
    }
}

/// Catch local storage up to the current chain tip for a deployment.
///
/// On a main RPC retention gap, syncs via `bootnode_url` until handoff, then
/// resumes on the main RPC.
pub(crate) async fn catch_up<S: Storage>(
    rpc: &RpcClient,
    storage: &S,
    contract_config: &ContractConfig,
    bootnode_url: Option<&str>,
) -> Result<(), Error> {
    let indexer = match Indexer::init(rpc.clone(), storage.fork()?, contract_config).await {
        Ok(indexer) => indexer,
        Err(e) if is_rpc_sync_gap(&e) => {
            bootnode_catch_up(storage, contract_config, bootnode_url, None).await?;
            Indexer::init(rpc.clone(), storage.fork()?, contract_config)
                .await
                .map_err(|e| Error::Other(format!("indexer: {e:#}")))?
        }
        Err(e) => return Err(Error::Other(format!("indexer: {e:#}"))),
    };
    indexer
        .catch_up()
        .await
        .map_err(|e| Error::Other(format!("indexer catch-up: {e:#}")))?;
    storage.process_pending_state().await
}

/// Poll until a submitted transaction succeeds or fails.
pub(crate) async fn confirm_tx(
    rpc: &RpcClient,
    hash: impl AsRef<str>,
) -> Result<TransactionResult, Error> {
    let hash = hash.as_ref();

    for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
        if attempt > 1 {
            sleep(CONFIRM_POLL_INTERVAL_MS).await;
        }
        match rpc_confirm_tx(rpc, hash)
            .await
            .map_err(|e| Error::Other(format!("confirm transaction: {e:#}")))?
        {
            TxConfirmStatus::Success => {
                return Ok(TransactionResult {
                    tx_hash: hash.to_string(),
                });
            }
            TxConfirmStatus::Failed { detail } => {
                return Err(Error::Other(format!("transaction failed{detail}")));
            }
            TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                return Err(Error::Other(format!(
                    "transaction confirmation timed out after 30s (hash: {hash})"
                )));
            }
            TxConfirmStatus::Pending => {}
        }
    }

    Err(Error::Other(format!(
        "transaction confirmation failed (hash: {hash})"
    )))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::chain::ContractDataStorage;
    use serde_json::json;
    use std::{
        cell::RefCell,
        rc::Rc,
        time::{Duration, Instant},
    };
    use types::{ContractsEventData, SyncMetadata};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method},
    };

    #[tokio::test]
    async fn sync_kick_interrupts_wait_timeout() {
        let kick = SyncKick::new(SyncMode::Inline);
        let kicker = kick.clone();
        let started = Instant::now();
        let waiter = tokio::spawn(async move {
            kick.wait_timeout(5_000).await;
        });
        tokio::task::yield_now().await;
        kicker.kick();
        waiter.await.expect("waiter join");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "kick should interrupt the 5s wait"
        );
    }

    #[tokio::test]
    async fn sync_mode_is_shared_across_clones() {
        let sync = SyncHandle::inline(None);
        let clone = sync.clone();
        assert_eq!(sync.mode(), SyncMode::Inline);
        assert_eq!(clone.mode(), SyncMode::Inline);
        sync.set_mode(SyncMode::Background);
        assert_eq!(sync.mode(), SyncMode::Background);
        assert_eq!(clone.mode(), SyncMode::Background);
    }

    const RPC_EVENT_ID: &str = "rpc-event-1";

    const TEST_CONFIG_JSON: &str = r#"{
        "network": "test",
        "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "verifiers": {
            "AB": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        },
        "public_key_registry": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "pools": [{
            "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "deploymentLedger": 1,
            "enabled": true,
            "policyFlags": ["allowlist", "blocklist"],
            "asset": {"kind": "native"}
        }]
    }"#;

    fn test_config() -> &'static ContractConfig {
        Box::leak(Box::new(
            serde_json::from_str(TEST_CONFIG_JSON).expect("test config"),
        ))
    }

    fn json_rpc_ok(result: serde_json::Value) -> serde_json::Value {
        json!({ "jsonrpc": "2.0", "id": 1, "result": result })
    }

    fn get_events_page(
        cursor: &str,
        events: serde_json::Value,
        latest_ledger: u32,
    ) -> serde_json::Value {
        json_rpc_ok(json!({
            "cursor": cursor,
            "events": events,
            "latestLedger": latest_ledger,
            "latestLedgerCloseTime": "2024-01-01T00:00:00Z",
            "oldestLedger": 1,
            "oldestLedgerCloseTime": "2024-01-01T00:00:00Z",
        }))
    }

    fn handoff_response() -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": RETENTION_HANDOFF_CODE,
                "message": "Continue syncing on your RPC endpoint",
                "data": { "fromLedger": 2_999_000 },
            }
        })
    }

    fn rpc_sync_gap_response() -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32602,
                "message": "startLedger must be within the ledger range: 100 - 3000000",
            }
        })
    }

    #[tokio::test]
    async fn get_contract_events_surfaces_handoff_as_jsonrpc_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(&server)
            .await;

        let client = RpcClient::new(&server.uri()).expect("client");
        let err = client
            .get_contract_events(&["C".into()], 1, 1, None)
            .await
            .expect_err("handoff should fail");
        assert!(is_retention_handoff(&err));
    }

    #[tokio::test]
    async fn get_contract_events_maps_sync_gap_to_rpc_sync_gap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rpc_sync_gap_response()))
            .mount(&server)
            .await;

        let client = RpcClient::new(&server.uri()).expect("client");
        let err = client
            .get_contract_events(&["C".into()], 1, 1, None)
            .await
            .expect_err("sync gap should fail");
        assert!(matches!(err, RpcError::RpcSyncGap(100)));
    }

    #[tokio::test]
    async fn get_contract_events_maps_ahead_of_tip_to_rpc_ahead() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rpc_sync_gap_response()))
            .mount(&server)
            .await;

        let client = RpcClient::new(&server.uri()).expect("client");
        // Request past the newest ledger in the error range → RpcAhead.
        let err = client
            .get_contract_events(&["C".into()], 3_000_001, 1, None)
            .await
            .expect_err("ahead should fail");
        assert!(matches!(err, RpcError::RpcAhead(3_000_000)));
    }

    #[tokio::test]
    async fn bootnode_handoff_round_trip() {
        let bootnode = MockServer::start().await;
        let config = test_config();

        Mock::given(method("POST"))
            .and(body_string_contains("getLatestLedger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json_rpc_ok(json!({
                "id": "latest",
                "protocolVersion": 22,
                "sequence": 3_000_000u32,
            }))))
            .mount(&bootnode)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "bootnode-cursor",
                json!([{
                    "type": "contract",
                    "ledger": 10,
                    "ledgerClosedAt": "2024-01-01T00:00:00Z",
                    "contractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
                    "id": RPC_EVENT_ID,
                    "pagingToken": "10-1",
                    "inSuccessfulContractCall": true,
                    "topic": [],
                    "value": "AAAAAA==",
                }]),
                3_000_000,
            )))
            .up_to_n_times(1)
            .mount(&bootnode)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("bootnode-cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(&bootnode)
            .await;

        #[derive(Clone)]
        struct MemStorage {
            sync: Rc<RefCell<Vec<SyncMetadata>>>,
            batches: Rc<RefCell<Vec<ContractsEventData>>>,
        }

        impl MemStorage {
            fn clear_indexing_cursors(&self) {
                let mut sync = self.sync.borrow_mut();
                for entry in sync.iter_mut() {
                    entry.cursor.clear();
                }
            }
        }

        #[async_trait::async_trait(?Send)]
        impl ContractDataStorage for MemStorage {
            async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
                Ok(self.sync.borrow().clone())
            }

            async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
                self.batches.borrow_mut().push(batch);
                Ok(())
            }

            async fn save_sync_progress(
                &self,
                metadata: Vec<SyncMetadata>,
                _fully_indexed: bool,
            ) -> anyhow::Result<()> {
                *self.sync.borrow_mut() = metadata;
                Ok(())
            }
        }

        let storage = MemStorage {
            sync: Rc::new(RefCell::new(vec![SyncMetadata {
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
                cursor: "bootnode-cursor".into(),
                last_indexed_ledger: 10,
                last_fully_indexed_ledger: 0,
            }])),
            batches: Rc::new(RefCell::new(Vec::new())),
        };

        let bootnode_client = RpcClient::new(&bootnode.uri()).expect("bootnode client");
        let bootnode_indexer = Indexer::init(bootnode_client, storage.clone(), config)
            .await
            .expect("bootnode indexer");
        let err = bootnode_indexer
            .fetch_contract_events()
            .await
            .expect_err("bootnode should hand off");
        assert!(
            err.downcast_ref::<RpcError>()
                .is_some_and(is_retention_handoff),
            "expected handoff, got {err:?}"
        );

        storage.clear_indexing_cursors();
        assert!(
            storage.sync.borrow()[0].cursor.is_empty(),
            "cursors should clear on handoff"
        );
        let _ = storage.batches;
    }
}

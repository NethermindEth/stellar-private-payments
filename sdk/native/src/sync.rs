use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    task::{Context, Poll},
};

use crate::{
    chain::{
        ContractDataStorage, INVALID_PARAMS_CODE, Indexer, IndexerError, RpcError, TxConfirmStatus,
        confirm_tx as rpc_confirm_tx,
    },
    types::{ContractConfig, SyncMetadata},
};
use anyhow::Context as _;
use futures::task::AtomicWaker;

use crate::{
    Error, Handle, RetentionGap, StorageHandle, chain::RpcClient, sleep::sleep,
    types::TransactionResult,
};

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;
const BACKGROUND_SYNC_INTERVAL_MS: u32 = 5_000;

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
pub(crate) struct SyncHandle {
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
    pub(crate) async fn ensure_synced(
        &self,
        rpc: &RpcClient,
        storage: &StorageHandle,
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
    stop: Handle<AtomicBool>,
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
pub struct BackgroundSync {
    rpc: RpcClient,
    storage: StorageHandle,
    contract_config: ContractConfig,
    bootnode_url: Option<String>,
    kick: Handle<SyncKick>,
    stop: Handle<AtomicBool>,
    interval_ms: u32,
}

impl BackgroundSync {
    pub(crate) fn new(
        rpc: RpcClient,
        storage: StorageHandle,
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
            stop: Handle::new(AtomicBool::new(false)),
            interval_ms: BACKGROUND_SYNC_INTERVAL_MS,
        }
    }

    /// Cloneable handle to stop this task (also wakes the idle wait).
    pub fn stop_handle(&self) -> BackgroundSyncStop {
        BackgroundSyncStop {
            stop: self.stop.clone(),
            kick: self.kick.clone(),
        }
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Long-running indexer loop. Polls until stopped or the future is dropped.
    ///
    /// Between rounds, waits up to [`BACKGROUND_SYNC_INTERVAL_MS`] or until
    /// [`SyncKick::kick`]. Each failed round in a row doubles the wait, up to
    /// 16 times the interval; a good round resets it.
    ///
    /// On a main RPC retention gap, syncs historical events via the optional
    /// bootnode until handoff, then resumes on the main RPC. Retries any error
    /// not listed below.
    ///
    /// # Errors
    ///
    /// Returns [`RetentionGap::SyncGap`] if no bootnode is configured, and
    /// [`RetentionGap::BootnodeFailed`] if the bootnode cannot be used.
    pub async fn run(self) -> Result<(), Error> {
        tracing::info!(
            "background sync starting (bootnode={})",
            self.bootnode_url.as_deref().unwrap_or("<none>")
        );

        let mut indexer = None;
        let mut consecutive_failures: u32 = 0;
        while !self.is_stopped() {
            if indexer.is_none() {
                match open_indexer(
                    &self.rpc,
                    &self.storage,
                    &self.contract_config,
                    self.bootnode_url.as_deref(),
                    Some(self.stop.as_ref()),
                )
                .await
                {
                    Ok(opened) => {
                        tracing::info!("background sync: main RPC indexer ready");
                        indexer = Some(opened);
                    }
                    Err(_) if self.is_stopped() => break,
                    Err(
                        e @ Error::RetentionGap(
                            RetentionGap::SyncGap | RetentionGap::BootnodeFailed(_),
                        ),
                    ) => return Err(e),
                    Err(e) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if consecutive_failures.is_power_of_two() {
                            tracing::warn!(
                                consecutive_failures,
                                "background sync could not open the indexer, retrying: {e:#}"
                            );
                        }
                    }
                }
            }
            if let Some(opened) = &indexer {
                match catch_up_loop(opened, &self.storage, Some(self.stop.as_ref())).await {
                    Ok(()) => consecutive_failures = 0,
                    Err(e) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if consecutive_failures.is_power_of_two() {
                            tracing::error!(
                                consecutive_failures,
                                "background sync failed, retrying: {e:#}"
                            );
                        }
                        if matches!(e, Error::Rpc(RpcError::RpcSyncGap(_))) {
                            indexer = None;
                        }
                    }
                }
            }
            self.kick
                .wait_timeout(retry_delay_ms(self.interval_ms, consecutive_failures))
                .await;
        }
        tracing::info!("background sync stopped");
        Ok(())
    }
}

/// Returns `base` doubled once per failure, up to 16 times `base`.
fn retry_delay_ms(base: u32, failures: u32) -> u32 {
    base.saturating_mul(2u32.saturating_pow(failures.min(4)))
}

fn retention_handoff_from_ledger(err: &RpcError) -> Option<u32> {
    match err {
        RpcError::RetentionHandoff { from_ledger } => Some(*from_ledger),
        _ => None,
    }
}

fn is_rpc_sync_gap(err: &IndexerError) -> bool {
    matches!(err, IndexerError::Rpc(RpcError::RpcSyncGap(_)))
}

async fn apply_bootnode_handoff(
    storage: &StorageHandle,
    contract_config: &ContractConfig,
    from_ledger: u32,
) -> Result<(), Error> {
    let metadata: Vec<SyncMetadata> = contract_config
        .all_contract_ids()
        .into_iter()
        .map(|contract_id| SyncMetadata {
            contract_id,
            cursor: String::new(),
            last_indexed_ledger: from_ledger,
            last_fully_indexed_ledger: 0,
        })
        .collect();
    storage
        .save_sync_progress(metadata, false)
        .await
        .context("handoff sync progress")?;
    storage.clear_indexing_cursors().await?;
    storage
        .clamp_last_fully_indexed_ledger(from_ledger)
        .await
        .context("handoff clamp fully indexed")?;
    tracing::info!(
        from_ledger,
        "bootnode handoff, resuming main RPC from cutoff"
    );
    Ok(())
}

async fn apply_bootnode_handoff_from_err(
    storage: &StorageHandle,
    contract_config: &ContractConfig,
    err: &RpcError,
) -> Result<(), Error> {
    let from_ledger = retention_handoff_from_ledger(err).ok_or_else(|| {
        Error::Other(anyhow::anyhow!(
            "bootnode handoff missing fromLedger in error data"
        ))
    })?;
    apply_bootnode_handoff(storage, contract_config, from_ledger).await
}

/// Probe whether the main RPC needs a historical-sync bootnode.
///
/// Returns `true` on an RPC retention gap, `false` when the RPC can serve
/// history. Other indexer init errors are returned as [`Err`].
pub async fn bootnode_required(
    rpc: &RpcClient,
    storage: &StorageHandle,
    contract_config: &ContractConfig,
) -> Result<bool, Error> {
    match Indexer::init(rpc.clone(), storage.fork()?, contract_config).await {
        Ok(_) => Ok(false),
        Err(e) if is_rpc_sync_gap(&e) => Ok(true),
        Err(e) => Err(anyhow::Error::from(e).context("bootnode probe").into()),
    }
}

/// Run indexer rounds until caught up, stopped, or an error.
///
/// When `stop` is set, returns `Ok(())` without draining further. Applies
/// pending state after each successful round.
async fn catch_up_loop<I>(
    indexer: &Indexer<I>,
    storage: &StorageHandle,
    stop: Option<&AtomicBool>,
) -> Result<(), Error>
where
    I: ContractDataStorage,
{
    loop {
        if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
            return Ok(());
        }
        let may_have_more = indexer.fetch_contract_events().await?;
        storage.process_pending_state().await?;
        if !may_have_more {
            return Ok(());
        }
    }
}

/// Classifies a bootnode error. Retrying cannot help a bootnode that serves
/// none of the requested contracts or lacks their history itself.
fn bootnode_gap(e: RpcError) -> RetentionGap {
    match e {
        RpcError::BootnodeNotReady(reason) => RetentionGap::BootnodeNotReady(reason),
        e @ (RpcError::JsonRpc {
            code: INVALID_PARAMS_CODE,
            ..
        }
        | RpcError::RpcSyncGap(_)) => RetentionGap::BootnodeFailed(e.to_string()),
        e => RetentionGap::BootnodeNotReady(e.to_string()),
    }
}

/// Sync historical range via bootnode until retention handoff, then clear
/// cursors for main RPC resume.
async fn bootnode_catch_up(
    storage: &StorageHandle,
    contract_config: &ContractConfig,
    bootnode_url: Option<&str>,
    stop: Option<&AtomicBool>,
) -> Result<(), Error> {
    let Some(bootnode) = bootnode_url else {
        return Err(RetentionGap::SyncGap.into());
    };

    tracing::info!("main RPC sync gap, trying bootnode at {bootnode}");
    storage.clear_indexing_cursors().await?;

    let bootnode_client =
        RpcClient::new(bootnode).map_err(|e| RetentionGap::BootnodeFailed(e.to_string()))?;

    let bootnode_indexer =
        match Indexer::init(bootnode_client, storage.fork()?, contract_config).await {
            Ok(indexer) => indexer,
            Err(IndexerError::Rpc(rpc_err @ RpcError::RetentionHandoff { .. })) => {
                apply_bootnode_handoff_from_err(storage, contract_config, &rpc_err).await?;
                return Ok(());
            }
            Err(IndexerError::Rpc(e)) => return Err(bootnode_gap(e).into()),
            Err(IndexerError::Other(e)) => return Err(e.into()),
        };

    loop {
        if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
            return Ok(());
        }
        match catch_up_loop(&bootnode_indexer, storage, stop).await {
            // Caught up to bootnode tip (or stopped): wait, then poll for
            // handoff.
            Ok(()) => {
                if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
                    return Ok(());
                }
                sleep(BACKGROUND_SYNC_INTERVAL_MS).await;
            }
            // bootnode handoff, use main RPC
            Err(Error::Rpc(rpc_err @ RpcError::RetentionHandoff { .. })) => {
                apply_bootnode_handoff_from_err(storage, contract_config, &rpc_err).await?;
                return Ok(());
            }
            Err(Error::Rpc(e)) => return Err(bootnode_gap(e).into()),
            Err(e) => return Err(e),
        }
    }
}

/// Opens the main RPC indexer, first catching up through the bootnode when the
/// main RPC has a retention gap.
async fn open_indexer(
    rpc: &RpcClient,
    storage: &StorageHandle,
    contract_config: &ContractConfig,
    bootnode_url: Option<&str>,
    stop: Option<&AtomicBool>,
) -> Result<Indexer<StorageHandle>, Error> {
    match Indexer::init(rpc.clone(), storage.fork()?, contract_config).await {
        Ok(indexer) => return Ok(indexer),
        Err(e) if is_rpc_sync_gap(&e) => {}
        Err(e) => return Err(anyhow::Error::from(e).context("indexer").into()),
    }
    bootnode_catch_up(storage, contract_config, bootnode_url, stop).await?;
    if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
        return Err(anyhow::anyhow!("stopped during bootnode catch-up").into());
    }
    match Indexer::init(rpc.clone(), storage.fork()?, contract_config).await {
        Ok(indexer) => Ok(indexer),
        // The handoff point is older than the main RPC keeps.
        Err(e) if is_rpc_sync_gap(&e) => Err(RetentionGap::BootnodeNotReady(e.to_string()).into()),
        Err(e) => Err(anyhow::Error::from(e).context("indexer").into()),
    }
}

/// Catch local storage up to the current chain tip for a deployment.
///
/// On a main RPC retention gap, syncs via `bootnode_url` until handoff, then
/// resumes on the main RPC.
pub(crate) async fn catch_up(
    rpc: &RpcClient,
    storage: &StorageHandle,
    contract_config: &ContractConfig,
    bootnode_url: Option<&str>,
) -> Result<(), Error> {
    let indexer = open_indexer(rpc, storage, contract_config, bootnode_url, None).await?;
    catch_up_loop(&indexer, storage, None)
        .await
        .context("indexer catch-up")
        .map_err(Into::into)
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
            .context("confirm transaction")?
        {
            TxConfirmStatus::Success => {
                return Ok(TransactionResult {
                    tx_hash: hash.to_string(),
                });
            }
            TxConfirmStatus::Failed { detail } => {
                return Err(Error::Other(anyhow::anyhow!("transaction failed{detail}")));
            }
            TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                return Err(Error::Other(anyhow::anyhow!(
                    "transaction confirmation timed out after 30s (hash: {hash})"
                )));
            }
            TxConfirmStatus::Pending => {}
        }
    }

    Err(Error::Other(anyhow::anyhow!(
        "transaction confirmation failed (hash: {hash})"
    )))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{
        chain::ContractDataStorage,
        types::{ContractsEventData, SyncMetadata},
    };
    use serde_json::json;
    use std::time::{Duration, Instant};
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
        "kdf_domain": "tests",
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

    const HANDOFF_LEDGER: u32 = 2_999_000;

    fn handoff_response() -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32002,
                "message": "Continue syncing on your RPC endpoint",
                "data": { "fromLedger": HANDOFF_LEDGER },
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
        assert!(matches!(
            err,
            RpcError::RetentionHandoff {
                from_ledger: HANDOFF_LEDGER
            }
        ));
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
            sync: std::sync::Arc<std::sync::Mutex<Vec<SyncMetadata>>>,
            batches: std::sync::Arc<std::sync::Mutex<Vec<ContractsEventData>>>,
        }

        impl MemStorage {
            async fn apply_handoff(&self, from_ledger: u32, contract_ids: &[String]) {
                let metadata: Vec<SyncMetadata> = contract_ids
                    .iter()
                    .map(|contract_id| SyncMetadata {
                        contract_id: contract_id.clone(),
                        cursor: String::new(),
                        last_indexed_ledger: from_ledger,
                        last_fully_indexed_ledger: 0,
                    })
                    .collect();
                self.save_sync_progress(metadata, false)
                    .await
                    .expect("save handoff progress");
                let mut sync = self.sync.lock().expect("lock poisoned");
                for entry in sync.iter_mut() {
                    entry.cursor.clear();
                }
            }
        }

        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl ContractDataStorage for MemStorage {
            async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
                Ok(self.sync.lock().expect("lock poisoned").clone())
            }

            async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
                self.batches.lock().expect("lock poisoned").push(batch);
                Ok(())
            }

            async fn save_sync_progress(
                &self,
                metadata: Vec<SyncMetadata>,
                _fully_indexed: bool,
            ) -> anyhow::Result<()> {
                *self.sync.lock().expect("lock poisoned") = metadata;
                Ok(())
            }
        }

        let storage = MemStorage {
            sync: std::sync::Arc::new(std::sync::Mutex::new(vec![SyncMetadata {
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
                cursor: "bootnode-cursor".into(),
                last_indexed_ledger: 10,
                last_fully_indexed_ledger: 0,
            }])),
            batches: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let bootnode_client = RpcClient::new(&bootnode.uri()).expect("bootnode client");
        let bootnode_indexer = Indexer::init(bootnode_client, storage.clone(), config)
            .await
            .expect("bootnode indexer");
        let err = bootnode_indexer
            .fetch_contract_events()
            .await
            .expect_err("bootnode should hand off");
        let IndexerError::Rpc(rpc_err) = &err else {
            panic!("expected handoff, got {err:?}");
        };
        assert!(
            retention_handoff_from_ledger(rpc_err).is_some(),
            "expected handoff, got {err:?}"
        );
        storage
            .apply_handoff(
                retention_handoff_from_ledger(rpc_err).expect("fromLedger"),
                &config.all_contract_ids(),
            )
            .await;
        assert!(
            storage.sync.lock().expect("lock poisoned")[0]
                .cursor
                .is_empty(),
            "cursors should clear on handoff"
        );
        assert_eq!(
            storage.sync.lock().expect("lock poisoned")[0].last_indexed_ledger,
            HANDOFF_LEDGER
        );
        let _ = storage.batches;
    }

    /// Distinct ids, so the handoff is checked for every contract.
    fn distinct_config() -> ContractConfig {
        serde_json::from_value(json!({
            "network": "test",
            "kdf_domain": "tests",
            "deployer": "GDEPLOYER",
            "admin": "GADMIN",
            "asp_membership": "CMEMBERSHIP",
            "asp_non_membership": "CNONMEMBERSHIP",
            "verifiers": {},
            "public_key_registry": "CREGISTRY",
            "pools": [{
                "poolContractId": "CPOOL",
                "tokenContractId": "CTOKEN",
                "deploymentLedger": 1,
                "enabled": true,
                "policyFlags": ["allowlist"],
                "asset": {"kind": "native"}
            }]
        }))
        .expect("config")
    }

    fn temp_storage(name: &str) -> StorageHandle {
        let path =
            std::env::temp_dir().join(format!("spp-sync-{name}-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        StorageHandle::from(
            crate::state::test_local_storage(path.to_string_lossy().as_ref())
                .expect("open storage"),
        )
    }

    fn json_rpc_error(code: i64, message: &str) -> serde_json::Value {
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } })
    }

    fn range_error(oldest: u32, newest: u32) -> serde_json::Value {
        json_rpc_error(
            -32_600,
            &format!("startLedger must be within the ledger range: {oldest} - {newest}"),
        )
    }

    fn not_ready_response() -> serde_json::Value {
        json_rpc_error(-32_004, "bootnode warming up; retry later")
    }

    /// Answers the nth `getEvents` call with `responses[n]`, then the last.
    async fn mount_get_events(server: &MockServer, responses: Vec<serde_json::Value>) {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(move |_: &wiremock::Request| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let response = responses
                    .get(n)
                    .or(responses.last())
                    .cloned()
                    .unwrap_or_default();
                ResponseTemplate::new(200).set_body_json(response)
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getLatestLedger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json_rpc_ok(json!({
                "id": "latest",
                "protocolVersion": 22,
                "sequence": 3_000_000u32,
            }))))
            .mount(server)
            .await;
    }

    async fn main_rpc_with_a_gap() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(|request: &wiremock::Request| {
                request.body_json::<serde_json::Value>().is_ok_and(|body| {
                    body["params"]["startLedger"]
                        .as_u64()
                        .is_some_and(|ledger| ledger < u64::from(HANDOFF_LEDGER))
                })
            })
            .respond_with(
                ResponseTemplate::new(200).set_body_json(range_error(HANDOFF_LEDGER, 3_000_000)),
            )
            .mount(&server)
            .await;
        mount_get_events(
            &server,
            vec![get_events_page("main-cursor", json!([]), HANDOFF_LEDGER)],
        )
        .await;
        server
    }

    async fn get_events_calls(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| String::from_utf8_lossy(&request.body).contains("getEvents"))
            .count()
    }

    fn background_sync(
        rpc: &MockServer,
        storage: &StorageHandle,
        bootnode_url: Option<String>,
    ) -> BackgroundSync {
        BackgroundSync::new(
            RpcClient::new(&rpc.uri()).expect("rpc client"),
            storage.clone(),
            distinct_config(),
            bootnode_url,
            SyncKick::new(SyncMode::Background),
        )
    }

    /// Kicks `sync` until `done` holds, then stops it and returns its result.
    async fn run_until(
        sync: BackgroundSync,
        storage: &StorageHandle,
        done: impl Fn(&[SyncMetadata]) -> bool,
    ) -> Result<(), Error> {
        let kick = sync.kick.clone();
        let stop = sync.stop_handle();
        let run = sync.run();
        futures::pin_mut!(run);
        let reached = async {
            loop {
                kick.kick();
                if done(&storage.get_sync_state().await.expect("sync state")) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        // Less than the 5 s sleep a kick cannot cut short.
        tokio::time::timeout(Duration::from_secs(4), async {
            tokio::select! {
                result = &mut run => {
                    panic!("background sync ended before the expected state: {result:?}")
                }
                () = reached => stop.request(),
            }
            run.await
        })
        .await
        .expect("background sync did not reach the expected state")
    }

    fn handed_off(rows: &[SyncMetadata]) -> bool {
        distinct_config().all_contract_ids().iter().all(|id| {
            rows.iter()
                .any(|row| &row.contract_id == id && row.last_indexed_ledger == HANDOFF_LEDGER)
        })
    }

    fn at_cursor(cursor: &str) -> impl Fn(&[SyncMetadata]) -> bool + '_ {
        move |rows: &[SyncMetadata]| !rows.is_empty() && rows.iter().all(|row| row.cursor == cursor)
    }

    /// `-32004` at the probe and again mid-catch-up.
    #[tokio::test]
    async fn background_sync_waits_while_the_bootnode_is_not_ready() {
        let rpc = main_rpc_with_a_gap().await;
        let bootnode = MockServer::start().await;
        let page = get_events_page("bootnode-cursor", json!([]), 3_000_000);
        mount_get_events(
            &bootnode,
            vec![
                not_ready_response(),
                page.clone(),
                page.clone(),
                not_ready_response(),
                page.clone(),
                page,
                handoff_response(),
            ],
        )
        .await;
        let storage = temp_storage("not-ready-wait");
        let sync = background_sync(&rpc, &storage, Some(bootnode.uri()));

        let result = run_until(sync, &storage, handed_off).await;

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(get_events_calls(&bootnode).await, 7);
    }

    #[tokio::test]
    async fn background_sync_retries_the_main_rpc_after_the_handoff() {
        let rpc = MockServer::start().await;
        mount_get_events(
            &rpc,
            vec![
                rpc_sync_gap_response(),
                json_rpc_error(-32_603, "upstream timeout"),
                get_events_page("main-cursor", json!([]), 3_000_000),
            ],
        )
        .await;
        let bootnode = MockServer::start().await;
        mount_get_events(&bootnode, vec![handoff_response()]).await;
        let storage = temp_storage("main-rpc-error");
        let sync = background_sync(&rpc, &storage, Some(bootnode.uri()));

        let result = run_until(sync, &storage, at_cursor("main-cursor")).await;

        assert!(result.is_ok(), "{result:?}");
    }

    /// The bootnode call shows that the indexer was reopened.
    #[tokio::test]
    async fn background_sync_returns_to_the_bootnode_after_falling_behind_the_rpc() {
        let rpc = MockServer::start().await;
        let before = get_events_page("before", json!([]), 2_990_000);
        let behind = range_error(2_995_000, 3_100_000);
        mount_get_events(
            &rpc,
            vec![
                before.clone(),
                before.clone(),
                before,
                behind.clone(),
                behind,
                get_events_page("after-handoff", json!([]), 3_000_000),
            ],
        )
        .await;
        let bootnode = MockServer::start().await;
        mount_get_events(&bootnode, vec![handoff_response()]).await;
        let storage = temp_storage("fell-behind");
        let sync = background_sync(&rpc, &storage, Some(bootnode.uri()));

        let result = run_until(sync, &storage, at_cursor("after-handoff")).await;

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(get_events_calls(&bootnode).await, 1);
    }

    #[tokio::test]
    async fn background_sync_ends_when_a_retry_cannot_help() {
        let refusing = MockServer::start().await;
        mount_get_events(
            &refusing,
            vec![json_rpc_error(-32_602, "unsupported filters")],
        )
        .await;
        let pruned = MockServer::start().await;
        mount_get_events(&pruned, vec![range_error(100, 3_000_000)]).await;

        for bootnode_url in [
            None,
            Some(refusing.uri()),
            Some(pruned.uri()),
            Some("localhost:8080".to_owned()),
        ] {
            let rpc = main_rpc_with_a_gap().await;
            let storage = temp_storage("no-retry");
            let sync = background_sync(&rpc, &storage, bootnode_url.clone());

            let result = tokio::time::timeout(Duration::from_secs(2), sync.run())
                .await
                .unwrap_or_else(|_| panic!("{bootnode_url:?}: background sync did not end"));

            assert!(
                matches!(
                    (&result, &bootnode_url),
                    (Err(Error::RetentionGap(RetentionGap::SyncGap)), None)
                        | (
                            Err(Error::RetentionGap(RetentionGap::BootnodeFailed(_))),
                            Some(_)
                        )
                ),
                "{bootnode_url:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn background_sync_stops_during_a_not_ready_wait() {
        let rpc = main_rpc_with_a_gap().await;
        let bootnode = MockServer::start().await;
        mount_get_events(&bootnode, vec![not_ready_response()]).await;
        let storage = temp_storage("stop-while-waiting");
        let sync = background_sync(&rpc, &storage, Some(bootnode.uri()));
        let stop = sync.stop_handle();

        let stop_once_asked = async {
            while get_events_calls(&bootnode).await == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            stop.request();
        };
        // Less than the 10 s retry wait: only the stop can end it.
        let (result, ()) = tokio::time::timeout(
            Duration::from_secs(2),
            futures::future::join(sync.run(), stop_once_asked),
        )
        .await
        .expect("stop ends the wait");

        assert!(result.is_ok(), "{result:?}");
    }

    /// Open and fetch failures share one count; a good round resets it.
    #[tokio::test]
    async fn background_sync_logs_failures_at_doubling_counts() {
        use tracing_subscriber::layer::SubscriberExt as _;

        struct Alerts(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Alerts {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let level = event.metadata().level();
                if *level <= tracing::Level::WARN {
                    let mut count = String::from("-");
                    event.record(
                        &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                            if field.name() == "consecutive_failures" {
                                count = format!("{value:?}");
                            }
                        },
                    );
                    self.0
                        .lock()
                        .expect("lock poisoned")
                        .push(format!("{level} {count}"));
                }
            }
        }

        let error = json_rpc_error(-32_603, "upstream timeout");
        let page = get_events_page("main-cursor", json!([]), 3_000_000);
        let rpc = MockServer::start().await;
        mount_get_events(
            &rpc,
            vec![
                error.clone(),
                error.clone(),
                error.clone(),
                page.clone(),
                error.clone(),
                page.clone(),
                page,
                error,
            ],
        )
        .await;
        let storage = temp_storage("doubling-logs");
        let sync = background_sync(&rpc, &storage, None);
        let kick = sync.kick.clone();
        let stop = sync.stop_handle();
        let alerts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(Alerts(alerts.clone())),
        );
        // Without it, `has_just_one` in tracing-core caches interest
        // from whichever test thread hits a callsite first.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());

        // 7 calls to the good round, then 9 failed fetches; next log at 16.
        // Kicks end even the 80 s retry wait.
        let fail_nine_fetches = async {
            while get_events_calls(&rpc).await < 16 {
                kick.kick();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            stop.request();
        };
        let (result, ()) = tokio::time::timeout(
            Duration::from_secs(4),
            futures::future::join(sync.run(), fail_nine_fetches),
        )
        .await
        .expect("background sync did not reach nine failed fetches");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            *alerts.lock().expect("lock poisoned"),
            [
                "WARN 1", "WARN 2", "ERROR 4", "ERROR 1", "ERROR 2", "ERROR 4", "ERROR 8"
            ]
        );
    }

    #[test]
    fn retry_delay_doubles_up_to_sixteen_times_the_interval() {
        let delays = [0, 1, 2, 3, 4, 5, u32::MAX].map(|failures| retry_delay_ms(5_000, failures));
        assert_eq!(
            delays,
            [5_000, 10_000, 20_000, 40_000, 80_000, 80_000, 80_000]
        );
    }

    /// No kicks, so only the timer paces the retries.
    #[tokio::test]
    async fn background_sync_backs_off_after_failures() {
        let rpc = MockServer::start().await;
        mount_get_events(&rpc, vec![json_rpc_error(-32_603, "upstream timeout")]).await;
        let storage = temp_storage("backoff");
        let mut sync = background_sync(&rpc, &storage, None);
        sync.interval_ms = 50;
        let stop = sync.stop_handle();

        // Rounds at 0, 0.1, 0.3 and 0.7 s; a fixed 50 ms wait gives about 20.
        let stop_later = async {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            stop.request();
        };
        let (result, ()) = tokio::time::timeout(
            Duration::from_secs(4),
            futures::future::join(sync.run(), stop_later),
        )
        .await
        .expect("stop ends the wait");

        assert!(result.is_ok(), "{result:?}");
        let calls = get_events_calls(&rpc).await;
        assert!((2..=8).contains(&calls), "{calls} getEvents calls");
    }

    /// Inline sync returns a transient bootnode error at once.
    #[tokio::test]
    async fn inline_sync_reports_a_bootnode_that_is_not_ready() {
        let page = get_events_page("bootnode-cursor", json!([]), 3_000_000);
        let db_error = json_rpc_error(-32_603, "db unavailable");
        for responses in [
            vec![page.clone(), page.clone(), not_ready_response()],
            vec![page.clone(), page, db_error.clone()],
            vec![db_error],
        ] {
            let calls = responses.len();
            let rpc = main_rpc_with_a_gap().await;
            let bootnode = MockServer::start().await;
            mount_get_events(&bootnode, responses).await;
            let storage = temp_storage("inline-not-ready");

            let result = tokio::time::timeout(
                Duration::from_secs(4),
                catch_up(
                    &RpcClient::new(&rpc.uri()).expect("rpc client"),
                    &storage,
                    &distinct_config(),
                    Some(&bootnode.uri()),
                ),
            )
            .await
            .expect("inline sync returns without retrying");

            assert!(
                matches!(
                    result,
                    Err(Error::RetentionGap(RetentionGap::BootnodeNotReady(_)))
                ),
                "{result:?}"
            );
            assert_eq!(get_events_calls(&bootnode).await, calls);
        }
    }

    #[tokio::test]
    async fn inline_sync_reports_a_handoff_older_than_the_rpc_keeps() {
        let rpc = MockServer::start().await;
        mount_get_events(&rpc, vec![range_error(HANDOFF_LEDGER + 1, 3_100_000)]).await;
        let bootnode = MockServer::start().await;
        mount_get_events(&bootnode, vec![handoff_response()]).await;
        let storage = temp_storage("handoff-outside-rpc");

        let result = catch_up(
            &RpcClient::new(&rpc.uri()).expect("rpc client"),
            &storage,
            &distinct_config(),
            Some(&bootnode.uri()),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(Error::RetentionGap(RetentionGap::BootnodeNotReady(_)))
            ),
            "{result:?}"
        );
    }

    async fn probe(rpc: &MockServer, storage: &StorageHandle) -> Result<bool, Error> {
        bootnode_required(
            &RpcClient::new(&rpc.uri()).expect("rpc client"),
            storage,
            &distinct_config(),
        )
        .await
    }

    /// Every contract synced up to `ledger`, with a cursor and fully indexed.
    async fn synced_to(storage: &StorageHandle, ledger: u32) {
        let rows = distinct_config()
            .all_contract_ids()
            .into_iter()
            .map(|contract_id| SyncMetadata {
                contract_id,
                cursor: "synced-cursor".into(),
                last_indexed_ledger: ledger,
                last_fully_indexed_ledger: ledger,
            })
            .collect();
        storage
            .save_sync_progress(rows, true)
            .await
            .expect("save sync progress");
    }

    #[tokio::test]
    async fn bootnode_required_is_false_when_the_rpc_has_the_history() {
        let rpc = MockServer::start().await;
        mount_get_events(
            &rpc,
            vec![get_events_page("main-cursor", json!([]), 3_000_000)],
        )
        .await;

        let required = probe(&rpc, &temp_storage("probe-history")).await;

        assert!(matches!(required, Ok(false)), "{required:?}");
        assert_eq!(get_events_calls(&rpc).await, 1);
    }

    #[tokio::test]
    async fn bootnode_required_is_true_on_a_retention_gap() {
        let rpc = main_rpc_with_a_gap().await;

        let required = probe(&rpc, &temp_storage("probe-gap")).await;

        assert!(matches!(required, Ok(true)), "{required:?}");
    }

    /// Storage past the RPC's events tip is caught up, not missing history.
    #[tokio::test]
    async fn bootnode_required_is_false_when_storage_is_ahead_of_the_rpc() {
        let rpc = MockServer::start().await;
        mount_get_events(&rpc, vec![range_error(100, 3_000_000)]).await;
        let storage = temp_storage("probe-ahead");
        synced_to(&storage, 3_000_500).await;

        let required = probe(&rpc, &storage).await;

        assert!(matches!(required, Ok(false)), "{required:?}");
    }

    #[tokio::test]
    async fn bootnode_required_returns_other_rpc_errors() {
        let rpc = MockServer::start().await;
        mount_get_events(&rpc, vec![json_rpc_error(-32_603, "upstream timeout")]).await;

        let required = probe(&rpc, &temp_storage("probe-error")).await;

        let Err(Error::Other(err)) = &required else {
            panic!("expected an untyped error, got {required:?}");
        };
        let message = format!("{err:#}");
        assert!(message.starts_with("bootnode probe: "), "{message}");
        assert!(message.contains("upstream timeout"), "{message}");
    }

    /// A `-32002` without `data.fromLedger` is not a handoff.
    #[tokio::test]
    async fn inline_sync_reports_a_handoff_without_a_from_ledger_as_not_ready() {
        let rpc = main_rpc_with_a_gap().await;
        let bootnode = MockServer::start().await;
        let page = get_events_page("bootnode-cursor", json!([]), 3_000_000);
        mount_get_events(
            &bootnode,
            vec![
                page.clone(),
                page,
                json_rpc_error(-32_002, "Continue syncing on your RPC endpoint"),
            ],
        )
        .await;
        let storage = temp_storage("handoff-no-ledger");

        let result = catch_up(
            &RpcClient::new(&rpc.uri()).expect("rpc client"),
            &storage,
            &distinct_config(),
            Some(&bootnode.uri()),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(Error::RetentionGap(RetentionGap::BootnodeNotReady(_)))
            ),
            "{result:?}"
        );
        let rows = storage.get_sync_state().await.expect("sync state");
        assert!(at_cursor("bootnode-cursor")(&rows), "{rows:?}");
        assert!(!handed_off(&rows), "{rows:?}");
        // Only the probe that found the gap.
        assert_eq!(get_events_calls(&rpc).await, 1);
    }

    /// Waits out the 5 s pause at the bootnode tip, which a kick cannot cut
    /// short.
    #[tokio::test]
    async fn inline_sync_waits_at_the_bootnode_tip_for_the_handoff() {
        let rpc = main_rpc_with_a_gap().await;
        let bootnode = MockServer::start().await;
        let page = get_events_page("bootnode-cursor", json!([]), 3_000_000);
        // Probe, then a round that ends at the tip, then the handoff.
        mount_get_events(
            &bootnode,
            vec![page.clone(), page.clone(), page, handoff_response()],
        )
        .await;
        let storage = temp_storage("inline-bootnode-tip");
        let started = Instant::now();

        // One 5 s pause, not a second one.
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            catch_up(
                &RpcClient::new(&rpc.uri()).expect("rpc client"),
                &storage,
                &distinct_config(),
                Some(&bootnode.uri()),
            ),
        )
        .await
        .expect("inline sync ends at the handoff");

        assert!(result.is_ok(), "{result:?}");
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert_eq!(get_events_calls(&bootnode).await, 4);
        // The main RPC resumed from the handoff ledger.
        let rows = storage.get_sync_state().await.expect("sync state");
        assert!(handed_off(&rows), "{rows:?}");
        assert!(at_cursor("main-cursor")(&rows), "{rows:?}");
    }

    #[tokio::test]
    async fn background_sync_stops_during_bootnode_catch_up_without_reopening_the_rpc() {
        let rpc = main_rpc_with_a_gap().await;
        let bootnode = MockServer::start().await;
        // A new cursor on every page, so the bootnode never reaches its tip.
        let pages: Vec<_> = (0..1_000)
            .map(|n| get_events_page(&format!("bootnode-{n}"), json!([]), 3_000_000))
            .collect();
        mount_get_events(&bootnode, pages).await;
        let storage = temp_storage("stop-during-bootnode");
        let sync = background_sync(&rpc, &storage, Some(bootnode.uri()));
        let stop = sync.stop_handle();

        let stop_once_catching_up = async {
            while get_events_calls(&bootnode).await < 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            stop.request();
        };
        let (result, ()) = tokio::time::timeout(
            Duration::from_secs(4),
            futures::future::join(sync.run(), stop_once_catching_up),
        )
        .await
        .expect("stop ends the bootnode catch-up");

        assert!(result.is_ok(), "{result:?}");
        // Only the probe that found the gap.
        assert_eq!(get_events_calls(&rpc).await, 1);
    }
}

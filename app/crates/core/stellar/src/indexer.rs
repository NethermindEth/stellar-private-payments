use crate::rpc::{Client, Error as RpcError};
use anyhow::{Result, anyhow};
use std::{cell::Cell, collections::HashSet};
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const PAGE_SIZE: usize = 300;
const MAX_PAGES_PER_ROUND: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncPhase {
    Rpc,
    Bootnode,
}

pub struct Indexer<S: ContractDataStorage> {
    rpc: Client,
    bootnode: Option<Client>,
    phase: Cell<SyncPhase>,
    storage: S,
    contract_ids: Vec<String>,
    min_pool_ledger: u32,
}

/// Contract IDs indexed by the app (enabled pools + ASP membership).
pub fn contract_ids_for_indexer(config: &ContractConfig) -> Vec<String> {
    config
        .pools
        .iter()
        .filter_map(|p| p.enabled.then_some(p.pool_contract_id.clone()))
        .chain(std::iter::once(config.asp_membership.clone()))
        .collect()
}

/// Earliest deployment ledger among enabled pools.
pub fn min_pool_ledger_for_indexer(config: &ContractConfig) -> Result<u32> {
    config
        .pools
        .iter()
        .filter(|p| p.enabled)
        .map(|p| p.deployment_ledger)
        .min()
        .ok_or_else(|| anyhow!("at least one pool should be enabled"))
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(
        rpc_url: &str,
        bootnode_url: Option<&str>,
        storage: S,
        config: &'static ContractConfig,
    ) -> Result<Self> {
        let rpc = Client::new(rpc_url)?;
        let min_pool_ledger = min_pool_ledger_for_indexer(config)?;
        let contract_ids = contract_ids_for_indexer(config);

        match rpc
            .get_contract_events(&contract_ids, min_pool_ledger, 1, None)
            .await
        {
            Ok(_) => Ok(Self {
                rpc,
                bootnode: None,
                phase: Cell::new(SyncPhase::Rpc),
                storage,
                contract_ids,
                min_pool_ledger,
            }),
            Err(RpcError::RpcSyncGap(oldest)) => {
                let Some(bootnode_url) = bootnode_url else {
                    return Err(anyhow!(
                        "RPC_SYNC_GAP oldest={oldest} deployment={0} rpc={rpc_url}\n\
Your RPC node retains events only back to ledger {oldest}, but indexing requires {0}. \
Use a different RPC, a fresher deployment, or configure a bootnode.",
                        min_pool_ledger
                    ));
                };
                let bootnode = Client::new(bootnode_url)?;
                bootnode
                    .get_contract_events(&contract_ids, min_pool_ledger, 1, None)
                    .await?;
                Ok(Self {
                    rpc,
                    bootnode: Some(bootnode),
                    phase: Cell::new(SyncPhase::Bootnode),
                    storage,
                    contract_ids,
                    min_pool_ledger,
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    fn events_client(&self) -> &Client {
        match self.phase.get() {
            SyncPhase::Bootnode => self
                .bootnode
                .as_ref()
                .expect("bootnode phase requires bootnode client"),
            SyncPhase::Rpc => &self.rpc,
        }
    }

    pub fn sync_phase(&self) -> SyncPhase {
        self.phase.get()
    }

    pub async fn fetch_contract_events(&self) -> Result<()> {
        let network_tip = self.events_client().get_latest_ledger().await?.sequence;
        let existing_sync = self.storage.get_sync_state().await?;
        let active_contract_ids: HashSet<&str> =
            self.contract_ids.iter().map(String::as_str).collect();
        let active_sync: Vec<_> = existing_sync
            .into_iter()
            .filter(|meta| active_contract_ids.contains(meta.contract_id.as_str()))
            .collect();

        let mut start_ledger = active_sync
            .iter()
            .map(|meta| meta.last_ledger)
            .min()
            .unwrap_or(self.min_pool_ledger);

        if active_sync
            .iter()
            .map(|meta| meta.last_ledger)
            .collect::<HashSet<_>>()
            .len()
            > 1
        {
            log::warn!(
                "[INDEXER] sync ledger divergence detected for {} active contracts; using min last_ledger={start_ledger}",
                active_sync.len()
            );
        }

        let unique_cursors: HashSet<&str> = active_sync
            .iter()
            .map(|meta| meta.cursor.as_str())
            .collect();
        let mut cursor = if unique_cursors.len() <= 1 {
            active_sync.first().map(|meta| meta.cursor.clone())
        } else {
            log::warn!(
                "[INDEXER] sync cursor divergence detected for {} active contracts; resetting cursor and replaying from ledger={start_ledger}",
                active_sync.len()
            );
            None
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}, phase={:?}",
                self.phase.get()
            );

            let (new_cursor, events, latest_ledger) = match self
                .events_client()
                .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, cursor.clone())
                .await
            {
                Err(RpcError::RetentionHandoff { from_ledger }) => {
                    if self.phase.get() != SyncPhase::Bootnode {
                        return Err(anyhow!(
                            "unexpected bootnode handoff at ledger {from_ledger}"
                        ));
                    }
                    log::info!(
                        "[INDEXER] bootnode archive complete at ledger {from_ledger}, resuming on main RPC"
                    );
                    self.phase.set(SyncPhase::Rpc);
                    start_ledger = from_ledger;
                    self.rpc
                        .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, None)
                        .await?
                }
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            };

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let is_empty = events.is_empty();

            self.storage
                .save_events_batch(ContractsEventData {
                    cursor: new_cursor.clone(),
                    latest_ledger,
                    events: events.into_iter().map(|e| e.into()).collect(),
                })
                .await?;

            self.storage
                .save_sync_progress(
                    self.contract_ids
                        .iter()
                        .map(|contract_id| SyncMetadata {
                            contract_id: contract_id.clone(),
                            cursor: new_cursor.clone(),
                            last_ledger: latest_ledger,
                        })
                        .collect(),
                    is_empty,
                )
                .await?;

            cursor = Some(new_cursor);
            if is_empty {
                break;
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
pub trait ContractDataStorage {
    /// Gets the last synced ledger and cursor for all contracts.
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>>;

    /// Sends a batch of events to be saved and waits for confirmation.
    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()>;

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()>;
}
impl From<crate::rpc::Event> for ContractEvent {
    fn from(val: crate::rpc::Event) -> Self {
        let crate::rpc::Event {
            id,
            ledger,
            contract_id,
            topic,
            value,
            ..
        } = val;
        ContractEvent {
            id,
            ledger,
            contract_id,
            topics: topic,
            value,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method},
    };

    const TEST_CONFIG_JSON: &str = r#"{
        "network": "test",
        "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "verifier": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "pools": [{
            "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "deploymentLedger": 1,
            "enabled": true,
            "asset": {"kind": "native"}
        }]
    }"#;

    const HANDOFF_LEDGER: u32 = 2_999_000;
    const RPC_EVENT_ID: &str = "rpc-event-1";

    fn test_config() -> &'static ContractConfig {
        Box::leak(Box::new(
            serde_json::from_str(TEST_CONFIG_JSON).expect("test config"),
        ))
    }

    fn json_rpc_ok(result: serde_json::Value) -> serde_json::Value {
        json!({ "jsonrpc": "2.0", "id": 1, "result": result })
    }

    fn latest_ledger_response(sequence: u32) -> serde_json::Value {
        json_rpc_ok(json!({
            "id": "test-ledger",
            "protocolVersion": 23,
            "sequence": sequence,
        }))
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
                "code": -32005,
                "message": "bootnode archive complete",
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

    struct RecordingStorage<'a> {
        batches: &'a RefCell<Vec<ContractsEventData>>,
    }

    #[async_trait::async_trait(?Send)]
    impl ContractDataStorage for RecordingStorage<'_> {
        async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
            Ok(vec![])
        }

        async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
            self.batches.borrow_mut().push(batch);
            Ok(())
        }

        async fn save_sync_progress(
            &self,
            _metadata: Vec<SyncMetadata>,
            _fully_indexed: bool,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    async fn mount_bootnode_mocks(server: &MockServer) {
        Mock::given(method("POST"))
            .and(body_string_contains("getLatestLedger"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(latest_ledger_response(3_000_000)),
            )
            .mount(server)
            .await;

        // init probe, then fetch handoff — both are getEvents from deployment ledger.
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "probe-cursor",
                json!([]),
                3_000_000,
            )))
            .up_to_n_times(1)
            .expect(1)
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(server)
            .await;
    }

    async fn mount_rpc_mocks(server: &MockServer, pool_contract_id: &str) {
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("\"startLedger\":1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rpc_sync_gap_response()))
            .expect(1)
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains(format!(
                "\"startLedger\":{HANDOFF_LEDGER}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "rpc-cursor",
                json!([{
                    "type": "contract",
                    "ledger": HANDOFF_LEDGER,
                    "ledgerClosedAt": "2024-01-01T00:00:00Z",
                    "contractId": pool_contract_id,
                    "id": RPC_EVENT_ID,
                    "topic": ["deposit"],
                    "value": "00",
                }]),
                3_000_000,
            )))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("rpc-cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "rpc-cursor-done",
                json!([]),
                3_000_000,
            )))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn bootnode_handoff() {
        let config = test_config();
        let pool_contract_id = config.pools[0].pool_contract_id.clone();

        let bootnode = MockServer::start().await;
        mount_bootnode_mocks(&bootnode).await;

        let rpc = MockServer::start().await;
        mount_rpc_mocks(&rpc, &pool_contract_id).await;

        let batches = RefCell::new(Vec::new());
        let storage = RecordingStorage { batches: &batches };
        let indexer = Indexer::init(&rpc.uri(), Some(&bootnode.uri()), storage, config)
            .await
            .expect("indexer");
        assert_eq!(indexer.sync_phase(), SyncPhase::Bootnode);

        indexer
            .fetch_contract_events()
            .await
            .expect("fetch should succeed after handoff");
        assert_eq!(indexer.sync_phase(), SyncPhase::Rpc);

        let batches = batches.borrow();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].events.len(), 1);
        assert_eq!(batches[0].events[0].id, RPC_EVENT_ID);
        assert_eq!(batches[0].cursor, "rpc-cursor");
        assert!(batches[1].events.is_empty());
    }
}

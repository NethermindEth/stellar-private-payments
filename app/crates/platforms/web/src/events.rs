use crate::client::WebClient;
use gloo_timers::future::TimeoutFuture;
use std::rc::Rc;
use stellar::{Client, Indexer, RpcError};
use types::ContractConfig;

const INDEXER_INTERVAL_MS: u32 = 5_000;

pub(crate) async fn events_listener(
    rpc_url: String,
    bootnode_url: Option<String>,
    storage: WebClient,
    config: &'static ContractConfig,
) {
    log::debug!("[EVENTS] listening");

    let contract_ids = config.pools_and_membership_contract_ids();
    let min_deployment_ledger = match config.min_deployment_ledger() {
        Ok(v) => v,
        Err(e) => {
            log::error!("[EVENTS] invalid deployment config: {e}");
            return;
        }
    };

    // Try main RPC; on sync gap, connect to bootnode.
    let rpc = match Client::new(&rpc_url) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[EVENTS] invalid RPC URL: {e}");
            return;
        }
    };

    let mut on_bootnode = false;
    let connect_url = match rpc
        .get_contract_events(&contract_ids, min_deployment_ledger, 1, None)
        .await
    {
        Ok(_) => rpc_url.clone(),
        Err(RpcError::RpcSyncGap(oldest)) => {
            let Some(ref bootnode) = bootnode_url else {
                log::error!(
                    "RPC_SYNC_GAP oldest={oldest} deployment={min_deployment_ledger} rpc={rpc_url}\n\
Your RPC node retains events only back to ledger {oldest}, but indexing requires {min_deployment_ledger}. \
Use a different RPC, a fresher deployment, or configure a bootnode."
                );
                return;
            };
            let bootnode_client = match Client::new(bootnode) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("[EVENTS] invalid bootnode URL: {e}");
                    return;
                }
            };
            if let Err(e) = bootnode_client
                .get_contract_events(&contract_ids, min_deployment_ledger, 1, None)
                .await
            {
                log::error!("[EVENTS] bootnode probe failed: {e}");
                return;
            }
            on_bootnode = true;
            bootnode.clone()
        }
        Err(e) => {
            log::error!("[EVENTS] RPC probe failed: {e}");
            return;
        }
    };

    let mut indexer = match Indexer::init(&connect_url, storage.clone(), config).await {
        Ok(indexer) => Rc::new(indexer),
        Err(e) => {
            log::error!("[EVENTS] init failed: {e}");
            return;
        }
    };

    let mut resume_at: Option<u32> = None;

    loop {
        match indexer.fetch_contract_events(resume_at.take()).await {
            Ok(()) => {}
            Err(e) if on_bootnode => match e.downcast_ref::<RpcError>() {
                Some(RpcError::RpcHandoff(from_ledger)) => {
                    log::info!(
                        "[EVENTS] bootnode handoff at ledger {from_ledger}, resuming on main RPC"
                    );
                    indexer = match Indexer::init(&rpc_url, storage.clone(), config).await {
                        Ok(indexer) => Rc::new(indexer),
                        Err(e) => {
                            log::error!("[EVENTS] main RPC init failed: {e}");
                            return;
                        }
                    };
                    on_bootnode = false;
                    resume_at = Some(*from_ledger);
                    continue;
                }
                _ => log::error!("[EVENTS] bootnode round failed: {e}"),
            },
            Err(e) => log::error!("[EVENTS] round failed: {e}"),
        }
        TimeoutFuture::new(INDEXER_INTERVAL_MS).await;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;
    use stellar::{BOOTNODE_HANDOFF_CODE, ContractDataStorage, Indexer, RpcError};
    use types::{ContractsEventData, SyncMetadata};
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

    fn test_config() -> ContractConfig {
        serde_json::from_str(TEST_CONFIG_JSON).expect("test config")
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
                "code": BOOTNODE_HANDOFF_CODE,
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
    async fn get_contract_events_maps_handoff_jsonrpc_to_rpc_handoff() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(&server)
            .await;

        let client = Client::new(&server.uri()).expect("client");
        let err = client
            .get_contract_events(&["CA".to_string()], 1, 1, None)
            .await
            .expect_err("handoff should fail");
        assert!(matches!(err, RpcError::RpcHandoff(HANDOFF_LEDGER)));
    }

    #[tokio::test]
    async fn get_contract_events_maps_sync_gap_to_rpc_sync_gap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rpc_sync_gap_response()))
            .mount(&server)
            .await;

        let client = Client::new(&server.uri()).expect("client");
        let err = client
            .get_contract_events(&["CA".to_string()], 1, 1, None)
            .await
            .expect_err("sync gap should fail");
        assert!(matches!(err, RpcError::RpcSyncGap(100)));
    }

    #[tokio::test]
    async fn bootnode_handoff_round_trip() {
        let config = Box::leak(Box::new(test_config()));
        let pool_contract_id = config.pools[0].pool_contract_id.clone();

        let bootnode = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getLatestLedger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json_rpc_ok(json!({
                "id": "test-ledger",
                "protocolVersion": 23,
                "sequence": 3_000_000,
            }))))
            .mount(&bootnode)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(&bootnode)
            .await;

        let wallet = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getLatestLedger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json_rpc_ok(json!({
                "id": "test-ledger",
                "protocolVersion": 23,
                "sequence": 3_000_000,
            }))))
            .mount(&wallet)
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
            .mount(&wallet)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("rpc-cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "rpc-cursor-done",
                json!([]),
                3_000_000,
            )))
            .mount(&wallet)
            .await;

        #[derive(Clone)]
        struct RecordingStorage {
            batches: Rc<RefCell<Vec<ContractsEventData>>>,
        }

        #[async_trait::async_trait(?Send)]
        impl ContractDataStorage for RecordingStorage {
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

        let storage = RecordingStorage {
            batches: Rc::new(RefCell::new(Vec::new())),
        };
        let batches = Rc::clone(&storage.batches);

        let bootnode_indexer = Indexer::init(&bootnode.uri(), storage.clone(), config)
            .await
            .expect("bootnode indexer");
        let err = bootnode_indexer
            .fetch_contract_events(None)
            .await
            .expect_err("bootnode should hand off");
        let from_ledger = match err.downcast_ref::<RpcError>() {
            Some(RpcError::RpcHandoff(ledger)) => *ledger,
            other => panic!("expected RpcHandoff, got {other:?}"),
        };

        let wallet_indexer = Indexer::init(&wallet.uri(), storage, config)
            .await
            .expect("wallet indexer");
        wallet_indexer
            .fetch_contract_events(Some(from_ledger))
            .await
            .expect("wallet fetch");

        let batches = batches.borrow();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].events.len(), 1);
        assert_eq!(batches[0].events[0].id, RPC_EVENT_ID);
        assert_eq!(batches[0].cursor, "rpc-cursor");
        assert!(batches[1].events.is_empty());
    }
}

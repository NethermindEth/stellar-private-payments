use crate::client::WebClient;
use gloo_timers::future::TimeoutFuture;
use stellar::{Indexer, RpcError};
use types::ContractConfig;

const INDEXER_INTERVAL_MS: u32 = 5_000;
/// Bootnode JSON-RPC code: historical range complete, continue on the wallet
/// RPC.
const RETENTION_HANDOFF_CODE: i64 = -32_002;

fn is_retention_handoff(err: &RpcError) -> bool {
    matches!(
        err,
        RpcError::JsonRpc {
            code: RETENTION_HANDOFF_CODE,
            ..
        }
    )
}

pub(crate) fn is_rpc_sync_gap(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RpcError>(),
        Some(RpcError::RpcSyncGap(_))
    )
}

/// Probes wallet RPC retention; returns a bootnode URL when one is needed and
/// consented.
pub(crate) async fn bootnode_check(
    rpc_url: &str,
    storage: WebClient,
    config: &'static ContractConfig,
    bootnode_url: Option<&str>,
) -> Result<Option<String>, anyhow::Error> {
    match Indexer::init(rpc_url, storage.clone(), config).await {
        Ok(_) => Ok(None),
        Err(e) if is_rpc_sync_gap(&e) => {
            let url = bootnode_url
                .map(str::to_string)
                .or(storage.stored_bootnode_url().await);
            match url {
                Some(url) => Ok(Some(url)),
                None => Err(anyhow::anyhow!("RPC_SYNC_GAP: {e}")),
            }
        }
        Err(e) => Err(e),
    }
}

fn is_retention_handoff_err(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RpcError>(),
        Some(rpc_err) if is_retention_handoff(rpc_err)
    )
}

pub(crate) async fn events_listener(
    rpc_url: String,
    bootnode_url: Option<String>,
    storage: WebClient,
    config: &'static ContractConfig,
) {
    log::debug!("[EVENTS] listening");

    if config.min_deployment_ledger().is_err() {
        log::error!("[EVENTS] invalid deployment config: at least one pool should be enabled");
        return;
    }

    let indexer = match Indexer::init(&rpc_url, storage.clone(), config).await {
        // rpc ok
        Ok(indexer) => indexer,
        // sync-gap, try bootnode
        Err(e) if is_rpc_sync_gap(&e) => {
            let Some(ref bootnode) = bootnode_url else {
                log::error!(
                    "[EVENTS] RPC sync gap: {e}\n\
Use a different RPC, a fresher deployment, or configure a bootnode."
                );
                return;
            };

            log::info!("[EVENTS] wallet RPC sync gap, trying bootnode");
            if let Err(e) = storage.clear_indexing_cursors().await {
                log::error!("[EVENTS] failed to clear indexing cursors: {e:?}");
                return;
            }

            let bootnode_indexer = match Indexer::init(bootnode, storage.clone(), config).await {
                Ok(indexer) => Some(indexer),
                Err(e) if is_retention_handoff_err(&e) => {
                    log::info!("[EVENTS] bootnode handoff, resuming on wallet RPC");
                    None
                }
                Err(e) => {
                    log::error!("[EVENTS] bootnode init failed: {e}");
                    return;
                }
            };

            // fetch bootnode events
            if let Some(indexer) = bootnode_indexer {
                loop {
                    match indexer.fetch_contract_events().await {
                        Ok(()) => {}
                        Err(e)
                            if e.downcast_ref::<RpcError>()
                                .is_some_and(is_retention_handoff) =>
                        {
                            log::info!("[EVENTS] bootnode handoff, resuming on wallet RPC");
                            if let Err(e) = storage.clear_indexing_cursors().await {
                                log::error!("[EVENTS] failed to clear indexing cursors: {e:?}");
                                continue;
                            }
                            break;
                        }
                        Err(e) => log::error!("[EVENTS] bootnode round failed: {e}"),
                    }
                    TimeoutFuture::new(INDEXER_INTERVAL_MS).await;
                }
            }

            // back to rpc
            match Indexer::init(&rpc_url, storage.clone(), config).await {
                Ok(indexer) => indexer,
                Err(e) => {
                    log::error!("[EVENTS] wallet RPC init failed: {e}");
                    return;
                }
            }
        }
        Err(e) => {
            log::error!("[EVENTS] init failed: {e}");
            return;
        }
    };

    // main rpc event listening loop
    loop {
        match indexer.fetch_contract_events().await {
            Ok(()) => {}
            Err(e) => log::error!("[EVENTS] round failed: {e}"),
        }
        TimeoutFuture::new(INDEXER_INTERVAL_MS).await;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{cell::RefCell, rc::Rc};
    use stellar::{Client, ContractDataStorage};
    use types::{ContractsEventData, SyncMetadata};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method},
    };

    const RPC_EVENT_ID: &str = "rpc-event-1";

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
            .and(body_string_contains("getEvents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(handoff_response()))
            .mount(&server)
            .await;

        let client = Client::new(&server.uri()).expect("client");
        let err = client
            .get_contract_events(&["CA".to_string()], 1, 1, None)
            .await
            .expect_err("handoff should fail");
        assert!(is_retention_handoff(&err));
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
        let config = test_config();
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
            .and(body_string_contains("\"startLedger\":1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "bootnode-cursor",
                json!([]),
                3_000_000,
            )))
            .mount(&bootnode)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("\"startLedger\":2999000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "bootnode-cursor",
                json!([]),
                3_000_000,
            )))
            .mount(&bootnode)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getEvents"))
            .and(body_string_contains("bootnode-cursor"))
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
            .and(body_string_contains("\"startLedger\":2999000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_events_page(
                "rpc-cursor",
                json!([{
                    "type": "contract",
                    "ledger": 2_999_000,
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
            sync: Rc<RefCell<Vec<SyncMetadata>>>,
        }

        impl RecordingStorage {
            fn clear_indexing_cursors(&self) {
                let mut sync = self.sync.borrow_mut();
                for entry in sync.iter_mut() {
                    entry.cursor.clear();
                }
            }
        }

        #[async_trait::async_trait(?Send)]
        impl ContractDataStorage for RecordingStorage {
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

        let storage = RecordingStorage {
            batches: Rc::new(RefCell::new(Vec::new())),
            sync: Rc::new(RefCell::new(vec![SyncMetadata {
                contract_id: pool_contract_id.clone(),
                cursor: "bootnode-cursor".into(),
                last_indexed_ledger: 2_999_000,
                last_fully_indexed_ledger: 0,
            }])),
        };
        let batches = Rc::clone(&storage.batches);

        let bootnode_indexer = Indexer::init(&bootnode.uri(), storage.clone(), config)
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
        let wallet_indexer = Indexer::init(&wallet.uri(), storage, config)
            .await
            .expect("wallet indexer");
        wallet_indexer
            .fetch_contract_events()
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

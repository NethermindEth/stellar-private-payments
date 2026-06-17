use bootnode::{
    Bootnode, InMemory,
    config::Config,
    metrics,
    rpc::RETENTION_HANDOFF_CODE,
    storage::{InsertGetEventsPage, Storage},
};
use serde_json::json;
use std::sync::{Arc, OnceLock};
use stellar::{Event, GetEventsParams, GetEventsResponse, JsonRpcRequest, JsonRpcResponse};
use types::ContractConfig;

fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| metrics::install_prometheus_recorder().expect("prometheus"))
        .clone()
}

fn test_config(port: u16) -> Config {
    Config {
        bind: format!("127.0.0.1:{port}").parse().expect("bind"),
        upstream_rpc_url: "http://127.0.0.1:9".parse().expect("upstream"),
        dev: true,
        tls: None,
        redirect_days: 5,
        ledger_seconds: 5,
        indexer_sleep_ms: 60_000,
        max_pages_per_round: 1,
        page_size: 300,
        rate_limit_rps: 1_000,
        rate_limit_burst: 1_000,
        otel: None,
    }
}

fn contract_ids() -> Vec<String> {
    let deployment: ContractConfig = serde_json::from_str(include_str!(
        "../../../deployments/testnet/deployments.json"
    ))
    .expect("deployments json");
    stellar::contract_ids_for_indexer(&deployment)
}

async fn wait_ready(client: &reqwest::Client, base: &str) {
    for _ in 0..50 {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server not ready");
}

async fn post_get_events(
    client: &reqwest::Client,
    base: &str,
    params: GetEventsParams,
) -> JsonRpcResponse<GetEventsResponse> {
    let body = JsonRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getEvents",
        params,
    };
    client
        .post(base)
        .json(&body)
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json body")
}

async fn spawn_bootnode(storage: Arc<InMemory>, port: u16) -> tokio::task::JoinHandle<()> {
    let bootnode = Bootnode::setup(test_config(port), storage, prom_handle())
        .await
        .expect("setup");
    tokio::spawn(async move {
        let _ = bootnode.serve().await;
    })
}

fn sample_event() -> Event {
    serde_json::from_value(json!({
        "type": "contract",
        "ledger": 2_999_000,
        "ledgerClosedAt": "2024-01-01T00:00:00Z",
        "contractId": contract_ids().into_iter().next().expect("pool id"),
        "id": "event-1",
        "topic": [],
        "value": "00",
    }))
    .expect("sample event")
}

#[tokio::test]
async fn cached_get_events() {
    const PORT: u16 = 40404;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 300);
    let cached = GetEventsResponse {
        cursor: "cursor-out".into(),
        events: vec![sample_event()],
        latest_ledger: 3_000_000,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: 2_997_687,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };

    let storage = Arc::new(InMemory::new());
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: Some("cursor-in"),
            start_ledger: None,
            request: &request,
            result: &cached,
            cursor_out: "cursor-out",
            last_event_ledger: Some(2_999_000),
            latest_ledger: cached.latest_ledger,
            oldest_ledger: cached.oldest_ledger,
        })
        .await
        .expect("seed cache");

    let server = spawn_bootnode(storage, PORT).await;

    let client = reqwest::Client::new();
    wait_ready(&client, &base).await;

    let response = post_get_events(&client, &base, request).await;

    server.abort();

    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    assert_eq!(response.result.expect("result").cursor, "cursor-out");
}

#[tokio::test]
async fn handoff_get_events() {
    const PORT: u16 = 40405;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 300);

    let storage = Arc::new(InMemory::new());
    let prev_request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 300);
    let prev = GetEventsResponse {
        cursor: "cursor-in".into(),
        events: vec![sample_event()],
        latest_ledger: 3_000_000,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: 2_997_687,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(2_997_687),
            request: &prev_request,
            result: &prev,
            cursor_out: "cursor-in",
            last_event_ledger: Some(2_999_000),
            latest_ledger: prev.latest_ledger,
            oldest_ledger: prev.oldest_ledger,
        })
        .await
        .expect("seed previous page for handoff cursor");

    let server = spawn_bootnode(storage, PORT).await;

    let client = reqwest::Client::new();
    wait_ready(&client, &base).await;

    let response = post_get_events(&client, &base, request).await;

    server.abort();

    assert!(
        response.result.is_none(),
        "unexpected result: {:?}",
        response.result
    );
    let err = response.error.expect("expected handoff error");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
    assert_eq!(
        err.data,
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": 0,
        }))
    );
}

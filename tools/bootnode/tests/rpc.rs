use bootnode::{
    Bootnode, InMemory,
    config::Config,
    messages::{Event, GetEventsParams, GetEventsResponse},
    metrics,
    rpc::{CACHE_MISS_CODE, RETENTION_HANDOFF_CODE},
    storage::{InsertGetEventsPage, Storage},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, OnceLock};
use types::ContractConfig;

const NETWORK_TIP: u32 = 3_000_000;
const HANDOFF_FROM_LEDGER: u32 = NETWORK_TIP - 86_400;

#[derive(Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
    error: Option<JsonRpcErr>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct JsonRpcErr {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| metrics::install_prometheus_recorder().expect("prometheus"))
        .clone()
}

fn test_config(port: u16, initial_ledger_tip: u32) -> Config {
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
        initial_ledger_tip,
    }
}

fn contract_ids() -> Vec<String> {
    let deployment: ContractConfig = serde_json::from_str(include_str!(
        "../../../deployments/testnet/deployments.json"
    ))
    .expect("deployments json");
    deployment.pools_and_membership_contract_ids()
}

async fn wait_listening(client: &reqwest::Client, base: &str) {
    for _ in 0..50 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server not listening");
}

async fn post_get_events(
    client: &reqwest::Client,
    base: &str,
    params: GetEventsParams,
) -> JsonRpcEnvelope<GetEventsResponse> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEvents",
        "params": params,
    });
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

async fn spawn_bootnode(storage: Arc<InMemory>, config: Config) -> tokio::task::JoinHandle<()> {
    let bootnode = Bootnode::setup(config, storage, prom_handle())
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
        latest_ledger: NETWORK_TIP,
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

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP)).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

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
        latest_ledger: NETWORK_TIP,
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

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP)).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

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
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );
}

// restart with warm cache and persisted ledger_tip; indexer hasn't run yet
#[tokio::test]
async fn request_on_warm_cache() {
    const PORT: u16 = 40406;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 300);
    let cached = GetEventsResponse {
        cursor: "cursor-out".into(),
        events: vec![sample_event()],
        latest_ledger: NETWORK_TIP,
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
    storage
        .set_ledger_tip(NETWORK_TIP)
        .await
        .expect("seed persisted tip");
    storage
        .mark_caught_up("cursor-out", NETWORK_TIP)
        .await
        .expect("seed indexer progress");

    let server = spawn_bootnode(storage, test_config(PORT, 0)).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let health = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .expect("healthz");
    assert_eq!(
        health.status(),
        200,
        "warm restart should hydrate ledger_tip"
    );

    let response = post_get_events(&client, &base, request).await;

    server.abort();

    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    assert_eq!(response.result.expect("result").cursor, "cursor-out");
}

// client arrives before the indexer has run and asks for data that isn’t cached
#[tokio::test]
async fn request_on_cold_cache() {
    const PORT: u16 = 40407;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 300);

    let server = spawn_bootnode(Arc::new(InMemory::new()), test_config(PORT, 0)).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(&client, &base, request).await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected warming-up error");
    assert_eq!(err.code, i64::from(CACHE_MISS_CODE));
    assert_eq!(err.message, "bootnode warming up; retry later");
}

#[tokio::test]
async fn handoff_when_in_sync() {
    const PORT: u16 = 40408;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 300);

    let storage = Arc::new(InMemory::new());
    let prev_request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 300);
    let prev = GetEventsResponse {
        cursor: "cursor-in".into(),
        events: vec![sample_event()],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: 2_997_687,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    let last_event_ledger = HANDOFF_FROM_LEDGER - 200;
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(2_997_687),
            request: &prev_request,
            result: &prev,
            cursor_out: "cursor-in",
            last_event_ledger: Some(last_event_ledger),
            latest_ledger: prev.latest_ledger,
            oldest_ledger: prev.oldest_ledger,
        })
        .await
        .expect("seed previous page for in-sync handoff");
    storage
        .mark_caught_up("cursor-in", NETWORK_TIP)
        .await
        .expect("indexer reached empty terminal page");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP)).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

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
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );
}

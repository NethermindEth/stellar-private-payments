use bootnode::{
    Bootnode, InMemory,
    config::Config,
    metrics,
    storage::{InsertGetEventsPage, Storage},
};
use std::{path::PathBuf, sync::Arc};
use stellar::{GetEventsParams, GetEventsResponse, JsonRpcRequest, JsonRpcResponse};
use types::ContractConfig;

const BASE: &str = "http://127.0.0.1:40404";

fn test_config() -> Config {
    Config {
        bind: "127.0.0.1:40404".parse().expect("bind"),
        upstream_rpc_url: "http://127.0.0.1:9".parse().expect("upstream"),
        dev: true,
        insecure_http: true,
        domain: None,
        acme_email: None,
        acme_cache_dir: PathBuf::from("/tmp/bootnode-test-acme"),
        acme_directory_url: None,
        redirect_days: 5,
        ledger_seconds: 5,
        indexer_sleep_ms: 60_000,
        max_pages_per_round: 1,
        page_size: 300,
        rate_limit_rps: 1_000,
        rate_limit_burst: 1_000,
        otel_enabled: false,
        otel_otlp_endpoint: None,
        otel_service_name: "bootnode-test".into(),
        otel_sample_ratio: 0.0,
    }
}

fn contract_ids() -> Vec<String> {
    let deployment: ContractConfig = serde_json::from_str(include_str!(
        "../../../deployments/testnet/deployments.json"
    ))
    .expect("deployments json");
    stellar::contract_ids_for_indexer(&deployment)
}

async fn wait_ready(client: &reqwest::Client) {
    for _ in 0..50 {
        if client
            .get(format!("{BASE}/healthz"))
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

#[tokio::test]
async fn cached_get_events() {
    let prom = metrics::install_prometheus_recorder().expect("prometheus");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 300);
    let cached = GetEventsResponse {
        cursor: "cursor-out".into(),
        events: vec![],
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
            last_event_ledger: None,
            latest_ledger: cached.latest_ledger,
            oldest_ledger: cached.oldest_ledger,
        })
        .await
        .expect("seed cache");

    let bootnode = Bootnode::setup(test_config(), storage, prom)
        .await
        .expect("setup");
    let server = tokio::spawn(async move {
        let _ = bootnode.serve().await;
    });

    let client = reqwest::Client::new();
    wait_ready(&client).await;

    let body = JsonRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getEvents",
        params: request,
    };
    let response: JsonRpcResponse<GetEventsResponse> = client
        .post(BASE)
        .json(&body)
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json body");

    server.abort();

    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    assert_eq!(response.result.expect("result").cursor, "cursor-out");
}

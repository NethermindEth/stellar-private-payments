//! Shared helpers for bootnode integration tests.
#![allow(dead_code)]

use bootnode::{
    Bootnode, DeploymentSpec, InMemory,
    config::Config,
    deployment_storage_id,
    messages::{Event, GetEventsParams, GetEventsResponse},
    metrics,
    storage::Storage,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, OnceLock};

pub const GENESIS_LEDGER: u32 = 2_800_000;
pub const NETWORK_TIP: u32 = 3_000_000;
/// Matches `Config::cutoff_ledgers()` for `redirect_days=5`,
/// `ledger_seconds=5`.
pub const HANDOFF_FROM_LEDGER: u32 = NETWORK_TIP - 86_400;

pub const FIXTURE_CONTRACT_IDS: &[&str] = &[
    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4",
];

#[derive(Deserialize)]
pub struct JsonRpcEnvelope<T> {
    pub result: Option<T>,
    pub error: Option<JsonRpcErr>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct JsonRpcErr {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

pub fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| metrics::install_prometheus_recorder().expect("prometheus"))
        .clone()
}

pub fn contract_ids() -> Vec<String> {
    FIXTURE_CONTRACT_IDS
        .iter()
        .map(|id| (*id).to_owned())
        .collect()
}

pub fn fixture_deployment(start_ledger: u32) -> DeploymentSpec {
    DeploymentSpec {
        contract_ids: contract_ids(),
        min_deployment_ledger: start_ledger,
    }
}

pub fn test_storage(start_ledger: u32) -> Arc<InMemory> {
    Arc::new(InMemory::with_deployment_id(deployment_storage_id(
        &contract_ids(),
        start_ledger,
    )))
}

pub fn test_config(port: u16, initial_ledger_tip: u32) -> Config {
    Config {
        bind: format!("127.0.0.1:{port}").parse().expect("bind"),
        upstream_rpc_url: "http://127.0.0.1:9".parse().expect("upstream"),
        dev: true,
        tls: None,
        redirect_days: 5,
        ledger_seconds: 5,
        indexer_sleep_ms: 60_000,
        max_pages_per_round: 1,
        page_size: 1000,
        rate_limit_rps: 1_000,
        rate_limit_burst: 1_000,
        otel: None,
        initial_ledger_tip,
        delete_other_deployments: false,
    }
}

pub async fn wait_listening(client: &reqwest::Client, base: &str) {
    for _ in 0..50 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server not listening");
}

pub async fn post_get_events(
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

pub async fn spawn_bootnode(
    storage: Arc<InMemory>,
    config: Config,
    start_ledger: u32,
) -> tokio::task::JoinHandle<()> {
    let bootnode = Bootnode::setup_with_deployment(
        config,
        storage,
        prom_handle(),
        fixture_deployment(start_ledger),
    )
    .await
    .expect("setup");
    tokio::spawn(async move {
        let _ = bootnode.serve().await;
    })
}

fn random_event_id(ledger: u32) -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("random event id");
    let suffix = u64::from_le_bytes(bytes);
    format!("event-{ledger:010}-{suffix:016x}")
}

pub fn sample_event() -> Event {
    sample_event_at(GENESIS_LEDGER + 10_000)
}

pub fn sample_event_at(ledger: u32) -> Event {
    serde_json::from_value(json!({
        "type": "contract",
        "ledger": ledger,
        "ledgerClosedAt": "2024-01-01T00:00:00Z",
        "contractId": FIXTURE_CONTRACT_IDS[0],
        "id": random_event_id(ledger),
        "topic": [],
        "value": "00",
    }))
    .expect("sample event")
}

pub async fn seed_events(storage: &InMemory, events: &[Event]) {
    storage.upsert_events(events).await.expect("seed events");
}

pub async fn seed_tip(storage: &InMemory, tip: u32) {
    storage.set_ledger_tip(tip).await.expect("seed tip");
}

pub async fn seed_archive_ready(storage: &InMemory) {
    storage
        .set_archive_ready()
        .await
        .expect("seed archive ready");
}

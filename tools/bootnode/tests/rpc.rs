use bootnode::{
    Bootnode, DeploymentSpec, InMemory,
    config::Config,
    deployment_storage_id,
    messages::{Event, GetEventsParams, GetEventsResponse},
    metrics,
    rpc::{CACHE_MISS_CODE, RETENTION_HANDOFF_CODE},
    storage::{InsertGetEventsPage, Storage},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, OnceLock};

const GENESIS_LEDGER: u32 = 2_800_000;
const NETWORK_TIP: u32 = 3_000_000;
const HANDOFF_FROM_LEDGER: u32 = NETWORK_TIP - 86_400;

const FIXTURE_CONTRACT_IDS: &[&str] = &[
    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4",
];

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

fn contract_ids() -> Vec<String> {
    FIXTURE_CONTRACT_IDS
        .iter()
        .map(|id| (*id).to_owned())
        .collect()
}

fn fixture_deployment(start_ledger: u32) -> DeploymentSpec {
    DeploymentSpec {
        contract_ids: contract_ids(),
        min_deployment_ledger: start_ledger,
    }
}

fn test_storage(start_ledger: u32) -> Arc<InMemory> {
    Arc::new(InMemory::with_deployment_id(deployment_storage_id(
        &contract_ids(),
        start_ledger,
    )))
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
        page_size: 1000,
        rate_limit_rps: 1_000,
        rate_limit_burst: 1_000,
        otel: None,
        initial_ledger_tip,
    }
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

async fn spawn_bootnode(
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

fn sample_event() -> Event {
    sample_event_at(2_999_000)
}

fn sample_event_at(ledger: u32) -> Event {
    serde_json::from_value(json!({
        "type": "contract",
        "ledger": ledger,
        "ledgerClosedAt": "2024-01-01T00:00:00Z",
        "contractId": FIXTURE_CONTRACT_IDS[0],
        "id": format!("event-{ledger}"),
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
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 1000);
    let cached = GetEventsResponse {
        cursor: "cursor-out".into(),
        events: vec![sample_event()],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: 2_997_687,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };

    let storage = test_storage(GENESIS_LEDGER);
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

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

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
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 1000);

    let storage = test_storage(GENESIS_LEDGER);
    let prev_request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 1000);
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
            last_event_ledger: Some(HANDOFF_FROM_LEDGER + 100),
            latest_ledger: prev.latest_ledger,
            oldest_ledger: prev.oldest_ledger,
        })
        .await
        .expect("seed previous page for handoff cursor");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

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
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 1000);
    let cached = GetEventsResponse {
        cursor: "cursor-out".into(),
        events: vec![sample_event()],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: 2_997_687,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };

    let storage = test_storage(GENESIS_LEDGER);
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

    let server = spawn_bootnode(storage, test_config(PORT, 0), GENESIS_LEDGER).await;

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
    let request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 1000);

    let server = spawn_bootnode(
        test_storage(GENESIS_LEDGER),
        test_config(PORT, 0),
        GENESIS_LEDGER,
    )
    .await;

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
    let request = GetEventsParams::for_contracts(&ids, None, Some("cursor-in"), 1000);

    let storage = test_storage(GENESIS_LEDGER);
    let prev_request = GetEventsParams::for_contracts(&ids, Some(2_997_687), None, 1000);
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

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

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

/// Genesis `startLedger` → follow cursor (page with event past cutoff) → next
/// cursor handoffs.
#[tokio::test]
async fn request_until_handoff() {
    const PORT: u16 = 40420;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);

    // second page
    let genesis_request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    let genesis_page = GetEventsResponse {
        cursor: "genesis-cursor".into(),
        events: vec![sample_event_at(GENESIS_LEDGER)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &genesis_request,
            result: &genesis_page,
            cursor_out: "genesis-cursor",
            last_event_ledger: Some(GENESIS_LEDGER),
            latest_ledger: genesis_page.latest_ledger,
            oldest_ledger: genesis_page.oldest_ledger,
        })
        .await
        .expect("seed genesis page");

    // third page (handoff)
    let next_ledger = HANDOFF_FROM_LEDGER + 1_000;
    let next_request = GetEventsParams::for_contracts(&ids, None, Some("genesis-cursor"), 1000);
    let next_page = GetEventsResponse {
        cursor: "next-cursor".into(),
        events: vec![sample_event_at(next_ledger)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: Some("genesis-cursor"),
            start_ledger: None,
            request: &next_request,
            result: &next_page,
            cursor_out: "next-cursor",
            last_event_ledger: Some(next_ledger),
            latest_ledger: next_page.latest_ledger,
            oldest_ledger: next_page.oldest_ledger,
        })
        .await
        .expect("seed page after genesis cursor");

    storage
        .mark_caught_up("next-cursor", NETWORK_TIP)
        .await
        .expect("indexer in sync");
    storage.set_ledger_tip(NETWORK_TIP).await.expect("tip");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // genesis
    let genesis = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000),
    )
    .await;
    assert!(
        genesis.error.is_none(),
        "unexpected error: {:?}",
        genesis.error
    );
    let genesis_cursor = genesis.result.expect("cached genesis").cursor;
    assert_eq!(genesis_cursor, "genesis-cursor");

    // next
    let next = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&genesis_cursor), 1000),
    )
    .await;
    assert!(next.error.is_none(), "unexpected error: {:?}", next.error);
    let next_cursor = next.result.expect("cached next page").cursor;
    assert_eq!(next_cursor, "next-cursor");

    // handoff
    let handoff = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&next_cursor), 1000),
    )
    .await;
    assert!(
        handoff.result.is_none(),
        "unexpected result: {:?}",
        handoff.result
    );
    let err = handoff.error.expect("expected retention handoff");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
    assert_eq!(
        err.data,
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );

    server.abort();
}

/// Empty tip page (cache hit) hands off when in sync, even if the prior
/// event ledger is still below cutoff — otherwise clients loop on 200 empties.
#[tokio::test]
async fn empty_tip_cursor_handoff_while_in_sync() {
    const PORT: u16 = 40422;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);

    let below_cutoff = HANDOFF_FROM_LEDGER - 1_000;
    let event_request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    let event_page = GetEventsResponse {
        cursor: "tip-cursor".into(),
        events: vec![sample_event_at(below_cutoff)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &event_request,
            result: &event_page,
            cursor_out: "tip-cursor",
            last_event_ledger: Some(below_cutoff),
            latest_ledger: event_page.latest_ledger,
            oldest_ledger: event_page.oldest_ledger,
        })
        .await
        .expect("seed event page");

    let empty_request = GetEventsParams::for_contracts(&ids, None, Some("tip-cursor"), 1000);
    let empty_page = GetEventsResponse {
        cursor: "tip-cursor".into(),
        events: vec![],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: Some("tip-cursor"),
            start_ledger: None,
            request: &empty_request,
            result: &empty_page,
            cursor_out: "tip-cursor",
            last_event_ledger: None,
            latest_ledger: empty_page.latest_ledger,
            oldest_ledger: empty_page.oldest_ledger,
        })
        .await
        .expect("seed empty tip page");

    storage
        .mark_caught_up("tip-cursor", NETWORK_TIP)
        .await
        .expect("in sync");
    storage.set_ledger_tip(NETWORK_TIP).await.expect("tip");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let handoff = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("tip-cursor"), 1000),
    )
    .await;
    server.abort();

    assert!(
        handoff.result.is_none(),
        "unexpected result: {:?}",
        handoff.result
    );
    let err = handoff.error.expect("expected retention handoff");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
    assert_eq!(
        err.data,
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );
}

/// Mid-history empty gap (with a later cached page) is served while in sync —
/// not handed off — so clients can keep walking the cursor chain.
#[tokio::test]
async fn mid_history_empty_served_while_in_sync() {
    const PORT: u16 = 40423;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);
    let below_cutoff = HANDOFF_FROM_LEDGER - 1_000;

    let genesis_request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    let genesis_page = GetEventsResponse {
        cursor: "gap-in".into(),
        events: vec![sample_event_at(GENESIS_LEDGER)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &genesis_request,
            result: &genesis_page,
            cursor_out: "gap-in",
            last_event_ledger: Some(GENESIS_LEDGER),
            latest_ledger: genesis_page.latest_ledger,
            oldest_ledger: genesis_page.oldest_ledger,
        })
        .await
        .expect("seed genesis");

    let gap_request = GetEventsParams::for_contracts(&ids, None, Some("gap-in"), 1000);
    let gap_page = GetEventsResponse {
        cursor: "after-gap".into(),
        events: vec![],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: Some("gap-in"),
            start_ledger: None,
            request: &gap_request,
            result: &gap_page,
            cursor_out: "after-gap",
            last_event_ledger: None,
            latest_ledger: gap_page.latest_ledger,
            oldest_ledger: gap_page.oldest_ledger,
        })
        .await
        .expect("seed empty gap");

    let after_request = GetEventsParams::for_contracts(&ids, None, Some("after-gap"), 1000);
    let after_page = GetEventsResponse {
        cursor: "tip-cursor".into(),
        events: vec![sample_event_at(below_cutoff)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: Some("after-gap"),
            start_ledger: None,
            request: &after_request,
            result: &after_page,
            cursor_out: "tip-cursor",
            last_event_ledger: Some(below_cutoff),
            latest_ledger: after_page.latest_ledger,
            oldest_ledger: after_page.oldest_ledger,
        })
        .await
        .expect("seed page after gap");

    storage
        .mark_caught_up("tip-cursor", NETWORK_TIP)
        .await
        .expect("in sync");
    storage.set_ledger_tip(NETWORK_TIP).await.expect("tip");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let gap = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("gap-in"), 1000),
    )
    .await;
    assert!(gap.error.is_none(), "unexpected error: {:?}", gap.error);
    let page = gap.result.expect("empty gap should be served");
    assert!(page.events.is_empty());
    assert_eq!(page.cursor, "after-gap");

    let after = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("after-gap"), 1000),
    )
    .await;
    server.abort();

    assert!(after.error.is_none(), "unexpected error: {:?}", after.error);
    let page = after.result.expect("events after gap");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.cursor, "tip-cursor");
}

/// Empty genesis page (no events ever) is served; next cursor hands off while
/// in sync.
#[tokio::test]
async fn request_empty_genesis_until_handoff() {
    const PORT: u16 = 40421;
    let base = format!("http://127.0.0.1:{PORT}");
    let start_ledger = GENESIS_LEDGER;

    let ids = contract_ids();
    let storage = test_storage(start_ledger);

    let genesis_request = GetEventsParams::for_contracts(&ids, Some(start_ledger), None, 1000);
    let empty_genesis = GetEventsResponse {
        cursor: "empty-cursor".into(),
        events: vec![],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: start_ledger,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    storage
        .insert_get_events_page(InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(start_ledger),
            request: &genesis_request,
            result: &empty_genesis,
            cursor_out: "empty-cursor",
            last_event_ledger: None,
            latest_ledger: empty_genesis.latest_ledger,
            oldest_ledger: empty_genesis.oldest_ledger,
        })
        .await
        .expect("seed empty genesis page");

    storage
        .mark_caught_up("empty-cursor", NETWORK_TIP)
        .await
        .expect("indexer in sync after empty tip page");
    storage.set_ledger_tip(NETWORK_TIP).await.expect("tip");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), start_ledger).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // empty page
    let genesis = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(start_ledger), None, 1000),
    )
    .await;
    assert!(
        genesis.error.is_none(),
        "unexpected error: {:?}",
        genesis.error
    );
    let page = genesis.result.expect("cached empty genesis");
    assert!(page.events.is_empty(), "expected no events ever");
    assert_eq!(page.cursor, "empty-cursor");

    // handoff
    let handoff = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&page.cursor), 1000),
    )
    .await;
    assert!(
        handoff.result.is_none(),
        "unexpected result: {:?}",
        handoff.result
    );
    let err = handoff.error.expect("expected retention handoff");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
    assert_eq!(
        err.data,
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );

    server.abort();
}

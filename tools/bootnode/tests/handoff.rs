mod common;

use bootnode::{
    InMemory,
    messages::{Event, GetEventsParams},
    storage::{GENESIS_CURSOR_PREFIX, Storage},
};
use common::*;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Starts an upstream whose `getEvents` reaches its tail once `at_tail` is set.
async fn spawn_upstream(
    tip: Arc<AtomicU32>,
    at_tail: Arc<AtomicBool>,
) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let tip = tip.load(Ordering::SeqCst);
            let mut body = if request["method"] == "getLatestLedger" {
                json!({"result": {"id": "tip", "protocolVersion": 22, "sequence": tip}})
            } else {
                let call = counter.fetch_add(1, Ordering::SeqCst);
                let cursor = if at_tail.load(Ordering::SeqCst) {
                    "upstream-tail".to_owned()
                } else {
                    format!("page-{call}")
                };
                json!({"result": {"events": [], "cursor": cursor, "latestLedger": tip,
                    "latestLedgerCloseTime": "", "oldestLedger": NETWORK_TIP,
                    "oldestLedgerCloseTime": ""}})
            };
            body["jsonrpc"] = "2.0".into();
            body["id"] = request["id"].clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream");
    });
    (url, calls)
}

async fn handoff_from(client: &reqwest::Client, base: &str, cursor: &str) -> Value {
    let response = post_get_events(
        client,
        base,
        GetEventsParams::for_contracts(&contract_ids(), None, Some(cursor), Some(10)),
    )
    .await;
    let data = response.error.and_then(|error| error.data);
    data.expect("handoff")["fromLedger"].clone()
}

async fn wait_for_handoff(client: &reqwest::Client, base: &str, cursor: &str, from_ledger: u32) {
    let mut handoff = handoff_from(client, base, cursor).await;
    for _ in 0..100 {
        if handoff == from_ledger {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        handoff = handoff_from(client, base, cursor).await;
    }
    assert_eq!(handoff, from_ledger);
}

/// Starts a bootnode whose archive holds `events` at `NETWORK_TIP`.
async fn serve_archive(port: u16, upstream_url: &str, events: &[Event]) -> Arc<InMemory> {
    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, events).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;
    storage
        .set_last_upstream_cursor("upstream-tail")
        .await
        .expect("cursor");
    let mut config = test_config(port, NETWORK_TIP);
    config.upstream_rpc_url = upstream_url.parse().expect("URL");
    config.indexer_sleep_ms = 20;
    spawn_bootnode(storage.clone(), config, GENESIS_LEDGER).await;
    wait_listening(&reqwest::Client::new(), &format!("http://127.0.0.1:{port}")).await;
    storage
}

#[tokio::test]
async fn handoff_moves_only_as_far_as_the_archive() {
    const PORT: u16 = 40450;
    const UPSTREAM_TIP: u32 = NETWORK_TIP + 100_000;
    let base = format!("http://127.0.0.1:{PORT}");
    let at_tail = Arc::new(AtomicBool::new(false));
    let (url, calls) =
        spawn_upstream(Arc::new(AtomicU32::new(UPSTREAM_TIP)), at_tail.clone()).await;

    let event = sample_event();
    let archive = serve_archive(PORT, &url, std::slice::from_ref(&event)).await;
    let client = reqwest::Client::new();

    wait_for(|| calls.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(
        handoff_from(&client, &base, &event.id).await,
        HANDOFF_FROM_LEDGER
    );
    let stored = archive.load_indexer_state().await.expect("state");
    assert_eq!(stored.ledger_tip, NETWORK_TIP);

    at_tail.store(true, Ordering::SeqCst);
    wait_for_handoff(&client, &base, &event.id, HANDOFF_FROM_LEDGER + 100_000).await;
    let stored = archive.load_indexer_state().await.expect("state");
    assert_eq!(stored.ledger_tip, UPSTREAM_TIP);
}

#[tokio::test]
async fn genesis_cursor_serves_events_below_the_moved_cutoff() {
    const PORT: u16 = 40451;
    let base = format!("http://127.0.0.1:{PORT}");
    let tip = Arc::new(AtomicU32::new(NETWORK_TIP));
    let (url, _) = spawn_upstream(tip.clone(), Arc::new(AtomicBool::new(true))).await;

    let event = sample_event_at(HANDOFF_FROM_LEDGER + 1);
    serve_archive(PORT, &url, &[sample_event(), event.clone()]).await;
    let client = reqwest::Client::new();

    let ids = contract_ids();
    let empty = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER + 20_000), None, Some(10)),
    )
    .await
    .result
    .expect("empty page");
    assert!(empty.events.is_empty());
    assert!(empty.cursor.starts_with(GENESIS_CURSOR_PREFIX));
    tip.store(NETWORK_TIP + 2, Ordering::SeqCst);
    wait_for_handoff(&client, &base, &event.id, HANDOFF_FROM_LEDGER + 2).await;
    let page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&empty.cursor), Some(10)),
    )
    .await;

    assert_eq!(page.error, None);
    let served: Vec<String> = page
        .result
        .expect("page")
        .events
        .into_iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(served, [event.id]);
}

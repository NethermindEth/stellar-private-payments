mod common;

use bootnode::storage::Storage;
use common::*;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const FIRST_TIP: u32 = NETWORK_TIP + 10;
const LAST_TIP: u32 = NETWORK_TIP + 50;

/// An upstream whose first `getEvents` advances the cursor at `FIRST_TIP` and
/// whose later ones sit at the tail at `LAST_TIP`. Returns the URL and the
/// number of `getLatestLedger` requests it received.
async fn spawn_upstream() -> (String, Arc<AtomicUsize>) {
    let latest_ledger_requests = Arc::new(AtomicUsize::new(0));
    let get_events_requests = Arc::new(AtomicUsize::new(0));
    let latest = latest_ledger_requests.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let mut body = if request["method"] == "getLatestLedger" {
                latest.fetch_add(1, Ordering::SeqCst);
                json!({"result": {"id": "tip", "protocolVersion": 22, "sequence": LAST_TIP}})
            } else {
                let call = get_events_requests.fetch_add(1, Ordering::SeqCst);
                let tip = if call == 0 { FIRST_TIP } else { LAST_TIP };
                json!({"result": {"events": [], "cursor": "page-0", "latestLedger": tip,
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
    (url, latest_ledger_requests)
}

#[tokio::test]
async fn the_tip_comes_from_the_events_page_that_reaches_the_tail() {
    const PORT: u16 = 40460;
    let (url, latest_ledger_requests) = spawn_upstream().await;

    let storage = test_storage(GENESIS_LEDGER);
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;
    storage
        .set_last_upstream_cursor("upstream-tail")
        .await
        .expect("cursor");
    let mut config = test_config(PORT, NETWORK_TIP);
    config.upstream_rpc_url = url.parse().expect("URL");
    config.indexer_sleep_ms = 20;
    let server = spawn_bootnode(storage.clone(), config, GENESIS_LEDGER).await;

    let mut tip = NETWORK_TIP;
    for _ in 0..100 {
        tip = storage
            .load_indexer_state()
            .await
            .expect("state")
            .ledger_tip;
        if tip != NETWORK_TIP {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Let a few caught-up rounds pass.
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.abort();

    // Not the first page's tip: only the page that reaches the tail sets it.
    assert_eq!(tip, LAST_TIP);
    assert_eq!(latest_ledger_requests.load(Ordering::SeqCst), 0);
}

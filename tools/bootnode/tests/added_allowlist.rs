mod common;

use bootnode::{
    Bootnode, InMemory,
    messages::{Event, GetEventsParams, GetEventsResponse},
    rpc::WARMING_UP_CODE,
    storage::Storage,
};
use common::*;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use stellar_private_payments::types::TreeConfigEntry;

const ALLOWLIST_A: &str = "CALLOWLISTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ALLOWLIST_B: &str = "CALLOWLISTBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const UPSTREAM_OLDEST: u32 = GENESIS_LEDGER + 1_000;

fn allowlist(contract_id: &str, deployment_ledger: u32) -> TreeConfigEntry {
    TreeConfigEntry {
        contract_id: contract_id.into(),
        deployment_ledger,
    }
}

/// An upstream holding one event per allowlist at its deployment ledger, served
/// one per page. Its `startLedger` replies wait while `open` is false.
struct Upstream {
    url: String,
    rounds: Arc<AtomicUsize>,
    backfills: Arc<AtomicUsize>,
    open: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

async fn upstream(trees: &[TreeConfigEntry]) -> Upstream {
    let events: Vec<Event> = trees
        .iter()
        .map(|tree| {
            let mut event = sample_event_at(tree.deployment_ledger);
            event.contract_id = tree.contract_id.clone();
            event
        })
        .collect();
    let (rounds, backfills) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let open = Arc::new(AtomicBool::new(true));
    let (r, b, o) = (rounds.clone(), backfills.clone(), open.clone());
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let (events, r, b, o) = (events.clone(), r.clone(), b.clone(), o.clone());
            async move {
                let params = &request["params"];
                let result = if request["method"] == "getLatestLedger" {
                    r.fetch_add(1, Ordering::SeqCst);
                    json!({"id": "tip", "protocolVersion": 22, "sequence": NETWORK_TIP})
                } else {
                    let page = |start: u64, served: usize| {
                        let page: Vec<Event> = events
                            .into_iter()
                            .filter(|e| u64::from(e.ledger) >= start)
                            .skip(served)
                            .take(1)
                            .collect();
                        let served = served.saturating_add(page.len());
                        (page, json!(format!("page:{start}:{served}")))
                    };
                    let cursor = params["pagination"]["cursor"].as_str().unwrap_or_default();
                    let parts: Vec<&str> = cursor.split(':').collect();
                    let (events, cursor) = match (params["startLedger"].as_u64(), &parts[..]) {
                        (Some(start), _) => {
                            b.fetch_add(1, Ordering::SeqCst);
                            while !o.load(Ordering::SeqCst) {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            page(start, 0)
                        }
                        (None, ["page", start, served]) => page(
                            start.parse().expect("start"),
                            served.parse().expect("served"),
                        ),
                        (None, _) => (vec![], json!(cursor)),
                    };
                    json!({"events": events, "cursor": cursor, "latestLedger": NETWORK_TIP,
                        "latestLedgerCloseTime": "", "oldestLedger": UPSTREAM_OLDEST,
                        "oldestLedgerCloseTime": ""})
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream");
    });
    Upstream {
        url,
        rounds,
        backfills,
        open,
        task,
    }
}

/// An archive in sync with its upstream that holds the `archived` allowlists.
async fn archive(archived: &[&str]) -> Arc<InMemory> {
    let archive = test_storage(GENESIS_LEDGER);
    seed_tip(&archive, NETWORK_TIP).await;
    seed_archive_ready(&archive).await;
    archive
        .set_last_upstream_cursor("archive-tip")
        .await
        .expect("cursor");
    let archived: Vec<String> = archived.iter().map(|id| (*id).to_owned()).collect();
    archive
        .set_archived_allowlists(&archived)
        .await
        .expect("archived allowlists");
    archive
}

async fn setup(
    port: u16,
    archive: &Arc<InMemory>,
    upstream_url: &str,
    trees: Vec<TreeConfigEntry>,
) -> Bootnode {
    let mut deployment = fixture_deployment(GENESIS_LEDGER);
    deployment
        .contract_ids
        .extend(trees.iter().map(|tree| tree.contract_id.clone()));
    deployment.added_allowlists = trees;
    let mut cfg = test_config(port, NETWORK_TIP);
    cfg.upstream_rpc_url = upstream_url.parse().expect("URL");
    cfg.indexer_sleep_ms = 10;
    Bootnode::setup_with_deployment(cfg, archive.clone(), prom_handle(), deployment)
        .await
        .expect("setup")
}

async fn serve(bootnode: Bootnode, port: u16) -> tokio::task::JoinHandle<()> {
    let server = tokio::spawn(async move {
        let _ = bootnode.serve().await;
    });
    wait_listening(&reqwest::Client::new(), &format!("http://127.0.0.1:{port}")).await;
    server
}

async fn events_of(
    port: u16,
    contract_ids: &[&str],
    from: u32,
) -> JsonRpcEnvelope<GetEventsResponse> {
    let contract_ids: Vec<String> = contract_ids.iter().map(|id| (*id).to_owned()).collect();
    post_get_events(
        &reqwest::Client::new(),
        &format!("http://127.0.0.1:{port}"),
        GetEventsParams::for_contracts(&contract_ids, Some(from), None, Some(10)),
    )
    .await
}

async fn wait_for(condition: impl Fn() -> bool) {
    for _ in 0..100 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn an_added_allowlist_is_refused_until_its_events_are_archived() {
    const PORT: u16 = 40440;
    let trees = vec![
        allowlist(ALLOWLIST_A, HANDOFF_FROM_LEDGER - 60_000),
        allowlist(ALLOWLIST_B, HANDOFF_FROM_LEDGER - 50_000),
    ];
    let from = trees[0].deployment_ledger;
    let upstream = upstream(&trees).await;
    upstream.open.store(false, Ordering::SeqCst);
    let archive = archive(&[]).await;
    let server = serve(setup(PORT, &archive, &upstream.url, trees).await, PORT).await;

    wait_for(|| upstream.backfills.load(Ordering::SeqCst) > 0).await;
    let refused = events_of(PORT, &[ALLOWLIST_B], from).await;
    upstream.open.store(true, Ordering::SeqCst);
    let mut served = events_of(PORT, &[ALLOWLIST_A, ALLOWLIST_B], from).await;
    for _ in 0..50 {
        if served.result.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        served = events_of(PORT, &[ALLOWLIST_A, ALLOWLIST_B], from).await;
    }
    let state = archive.load_indexer_state().await.expect("state");
    server.abort();
    upstream.task.abort();

    let error = refused.error.expect("refused");
    assert_eq!(error.code, i64::from(WARMING_UP_CODE));
    assert_eq!(
        error.message,
        format!(
            "the bootnode is still fetching the events of allowlist {ALLOWLIST_B}; retry later"
        )
    );
    let events = served.result.expect("served").events;
    let contracts: Vec<&str> = events.iter().map(|e| e.contract_id.as_str()).collect();
    assert_eq!(contracts, [ALLOWLIST_A, ALLOWLIST_B]);
    assert_eq!(state.archived_allowlists, [ALLOWLIST_A, ALLOWLIST_B]);
}

#[tokio::test]
async fn only_an_allowlist_older_than_upstream_retention_is_refused() {
    const PORT: u16 = 40441;
    let (lost, kept) = (UPSTREAM_OLDEST - 1, UPSTREAM_OLDEST + 10);
    let trees = vec![allowlist(ALLOWLIST_A, lost), allowlist(ALLOWLIST_B, kept)];
    let upstream = upstream(&trees).await;
    let archive = archive(&[]).await;
    let server = serve(setup(PORT, &archive, &upstream.url, trees).await, PORT).await;

    // A second round starts only after the first round's backfill returns.
    wait_for(|| upstream.rounds.load(Ordering::SeqCst) >= 2).await;
    let refused = events_of(PORT, &[ALLOWLIST_A], lost).await;
    let served = events_of(PORT, &[ALLOWLIST_B], lost).await;
    let state = archive.load_indexer_state().await.expect("state");
    server.abort();
    upstream.task.abort();

    let error = refused.error.expect("refused");
    assert_eq!(error.code, i64::from(WARMING_UP_CODE));
    assert_eq!(
        error.message,
        format!(
            "the bootnode's upstream no longer holds the deployment ledger of allowlist {ALLOWLIST_A}; retry once the bootnode restarts with an RPC that does"
        )
    );
    let events = served.result.expect("served").events;
    let contracts: Vec<&str> = events.iter().map(|e| e.contract_id.as_str()).collect();
    assert_eq!(contracts, [ALLOWLIST_B]);
    assert_eq!(state.archived_allowlists, [ALLOWLIST_B]);
}

#[tokio::test]
async fn startup_forgets_removed_allowlists_and_trusts_an_empty_archive() {
    let a = allowlist(ALLOWLIST_A, GENESIS_LEDGER);
    let b = allowlist(ALLOWLIST_B, GENESIS_LEDGER);

    let kept = archive(&[ALLOWLIST_A, ALLOWLIST_B]).await;
    setup(0, &kept, "http://127.0.0.1:9", vec![a.clone()]).await;
    let state = kept.load_indexer_state().await.expect("state");
    assert_eq!(state.archived_allowlists, [ALLOWLIST_A]);

    let empty = test_storage(GENESIS_LEDGER);
    setup(0, &empty, "http://127.0.0.1:9", vec![a, b]).await;
    let state = empty.load_indexer_state().await.expect("state");
    assert_eq!(state.archived_allowlists, [ALLOWLIST_A, ALLOWLIST_B]);
}

//! Empty-page compression: storage policy + RPC still serves the spliced chain.

mod common;

use bootnode::{
    messages::{GetEventsParams, GetEventsResponse},
    rpc::CACHE_MISS_CODE,
    storage::{InsertGetEventsPage, Storage},
};
use common::*;

/// Tip-suffix empties in the handoff window collapse; clients still walk the
/// spliced chain (events → merged empty), and the deleted middle cursor misses.
#[tokio::test]
async fn compress_tip_suffix_then_rpc_serves_spliced_chain() {
    const PORT: u16 = 40501;
    let base = format!("http://127.0.0.1:{PORT}");
    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);

    let below_cutoff = HANDOFF_FROM_LEDGER - 1_000;
    let events_request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    let events_page = GetEventsResponse {
        cursor: "e1".into(),
        events: vec![sample_event_at(below_cutoff)],
        latest_ledger: below_cutoff,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &events_request,
            result: &events_page,
            cursor_out: "e1",
            last_event_ledger: Some(below_cutoff),
            latest_ledger: events_page.latest_ledger,
            oldest_ledger: events_page.oldest_ledger,
        },
    )
    .await;

    let empty1 = empty_response("c1", HANDOFF_FROM_LEDGER + 1_000);
    let empty1_req = GetEventsParams::for_contracts(&ids, None, Some("e1"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("e1"),
            start_ledger: None,
            request: &empty1_req,
            result: &empty1,
            cursor_out: "c1",
            last_event_ledger: None,
            latest_ledger: empty1.latest_ledger,
            oldest_ledger: empty1.oldest_ledger,
        },
    )
    .await;

    let empty2 = empty_response("c2", NETWORK_TIP);
    let empty2_req = GetEventsParams::for_contracts(&ids, None, Some("c1"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("c1"),
            start_ledger: None,
            request: &empty2_req,
            result: &empty2,
            cursor_out: "c2",
            last_event_ledger: None,
            latest_ledger: empty2.latest_ledger,
            oldest_ledger: empty2.oldest_ledger,
        },
    )
    .await;

    let stats = storage
        .compress_empty_pages(HANDOFF_FROM_LEDGER)
        .await
        .expect("compress");
    assert_eq!(stats.spans_joined, 1);
    assert_eq!(stats.pages_removed, 1);
    assert!(
        storage
            .get_cached_get_events_by_cursor("c1")
            .await
            .expect("lookup")
            .is_none(),
        "middle empty page must be deleted"
    );

    // Leave `in_sync` false so the merged tip empty is served as a normal
    // cache hit (while caught up it would hand off as a terminal empty).
    storage
        .set_ledger_tip(NETWORK_TIP)
        .await
        .expect("ledger tip");

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

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
    assert_eq!(genesis.result.expect("genesis").cursor, "e1");

    // Spliced empty: first empty kept, cursor_out jumps to former last page.
    let merged = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("e1"), 1000),
    )
    .await;
    assert!(
        merged.error.is_none(),
        "unexpected error: {:?}",
        merged.error
    );
    let merged = merged.result.expect("merged empty");
    assert!(merged.events.is_empty());
    assert_eq!(merged.cursor, "c2");

    // Deleted middle cursor is a cache miss.
    let middle = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("c1"), 1000),
    )
    .await;
    assert!(
        middle.result.is_none(),
        "deleted middle cursor should not serve a page: {:?}",
        middle.result
    );
    let err = middle.error.expect("expected cache miss");
    assert_eq!(err.code, i64::from(CACHE_MISS_CODE));

    server.abort();
}

#[tokio::test]
async fn compress_leaves_historical_empty_run_below_cutoff() {
    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);

    let r1 = empty_response("c1", HANDOFF_FROM_LEDGER - 200);
    let req1 = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &req1,
            result: &r1,
            cursor_out: "c1",
            last_event_ledger: None,
            latest_ledger: r1.latest_ledger,
            oldest_ledger: r1.oldest_ledger,
        },
    )
    .await;

    let r2 = empty_response("c2", HANDOFF_FROM_LEDGER - 100);
    let req2 = GetEventsParams::for_contracts(&ids, None, Some("c1"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("c1"),
            start_ledger: None,
            request: &req2,
            result: &r2,
            cursor_out: "c2",
            last_event_ledger: None,
            latest_ledger: r2.latest_ledger,
            oldest_ledger: r2.oldest_ledger,
        },
    )
    .await;

    let r3 = empty_response("c3", HANDOFF_FROM_LEDGER - 1);
    let req3 = GetEventsParams::for_contracts(&ids, None, Some("c2"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("c2"),
            start_ledger: None,
            request: &req3,
            result: &r3,
            cursor_out: "c3",
            last_event_ledger: None,
            latest_ledger: r3.latest_ledger,
            oldest_ledger: r3.oldest_ledger,
        },
    )
    .await;

    let stats = storage
        .compress_empty_pages(HANDOFF_FROM_LEDGER)
        .await
        .expect("compress");
    assert_eq!(stats.spans_joined, 0);
    assert_eq!(stats.pages_removed, 0);
    assert!(
        storage
            .get_cached_get_events_by_cursor("c1")
            .await
            .expect("lookup")
            .is_some()
    );
    assert!(
        storage
            .get_cached_get_events_by_cursor("c2")
            .await
            .expect("lookup")
            .is_some()
    );
}

#[tokio::test]
async fn compress_leaves_mid_history_empties_with_tip_latest_ledger() {
    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);

    let early = GetEventsResponse {
        cursor: "e1".into(),
        events: vec![sample_event_at(GENESIS_LEDGER)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    let early_req = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: None,
            start_ledger: Some(GENESIS_LEDGER),
            request: &early_req,
            result: &early,
            cursor_out: "e1",
            last_event_ledger: Some(GENESIS_LEDGER),
            latest_ledger: early.latest_ledger,
            oldest_ledger: early.oldest_ledger,
        },
    )
    .await;

    let gap1 = empty_response("c1", NETWORK_TIP);
    let gap1_req = GetEventsParams::for_contracts(&ids, None, Some("e1"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("e1"),
            start_ledger: None,
            request: &gap1_req,
            result: &gap1,
            cursor_out: "c1",
            last_event_ledger: None,
            latest_ledger: gap1.latest_ledger,
            oldest_ledger: gap1.oldest_ledger,
        },
    )
    .await;

    let gap2 = empty_response("c2", NETWORK_TIP);
    let gap2_req = GetEventsParams::for_contracts(&ids, None, Some("c1"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("c1"),
            start_ledger: None,
            request: &gap2_req,
            result: &gap2,
            cursor_out: "c2",
            last_event_ledger: None,
            latest_ledger: gap2.latest_ledger,
            oldest_ledger: gap2.oldest_ledger,
        },
    )
    .await;

    let later_ledger = GENESIS_LEDGER + 10_000;
    let later = GetEventsResponse {
        cursor: "e2".into(),
        events: vec![sample_event_at(later_ledger)],
        latest_ledger: NETWORK_TIP,
        latest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
        oldest_ledger: GENESIS_LEDGER,
        oldest_ledger_close_time: "2024-01-01T00:00:00Z".into(),
    };
    let later_req = GetEventsParams::for_contracts(&ids, None, Some("c2"), 1000);
    insert_page(
        &storage,
        InsertGetEventsPage {
            cursor_in: Some("c2"),
            start_ledger: None,
            request: &later_req,
            result: &later,
            cursor_out: "e2",
            last_event_ledger: Some(later_ledger),
            latest_ledger: later.latest_ledger,
            oldest_ledger: later.oldest_ledger,
        },
    )
    .await;

    let stats = storage
        .compress_empty_pages(HANDOFF_FROM_LEDGER)
        .await
        .expect("compress");
    assert_eq!(stats.spans_joined, 0);
    assert_eq!(stats.pages_removed, 0);
    assert!(
        storage
            .get_cached_get_events_by_cursor("c1")
            .await
            .expect("lookup")
            .is_some(),
        "mid-history empties must stay for cold catch-up"
    );
}

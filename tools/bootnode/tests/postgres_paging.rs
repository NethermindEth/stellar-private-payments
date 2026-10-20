mod common;

use bootnode::{Postgres, storage::Storage};
use common::*;

/// Run with `BOOTNODE_TEST_DATABASE_URL=... cargo test -- --ignored`.
#[tokio::test]
#[ignore = "needs BOOTNODE_TEST_DATABASE_URL"]
async fn postgres_pages_only_the_requested_contracts() {
    let url = std::env::var("BOOTNODE_TEST_DATABASE_URL").expect("BOOTNODE_TEST_DATABASE_URL");
    // Fresh namespace per run; event IDs are random.
    let namespace = format!("postgres-paging-{}", sample_event().id);
    let storage = Postgres::connect(&url, 4, &namespace, false)
        .await
        .expect("connect");
    storage.init().await.expect("init");
    let ids = contract_ids();
    let first = sample_event_at(GENESIS_LEDGER + 1_000);
    let mut other = sample_event_at(GENESIS_LEDGER + 1_500);
    other.contract_id = ids[1].clone();
    let second = sample_event_at(GENESIS_LEDGER + 2_000);
    let past_cutoff = sample_event_at(HANDOFF_FROM_LEDGER);
    storage
        .upsert_events(&[first.clone(), other.clone(), second.clone(), past_cutoff])
        .await
        .expect("seed");
    let pool = [ids[0].clone()];

    let page = storage
        .page_events_ledger(&pool, GENESIS_LEDGER, HANDOFF_FROM_LEDGER, 10)
        .await
        .expect("ledger page");
    let limited = storage
        .page_events_ledger(&[ids[1].clone()], GENESIS_LEDGER, HANDOFF_FROM_LEDGER, 1)
        .await
        .expect("limited page");
    let (cursor_ledger, after_other) = storage
        .page_events_cursor(&pool, &other.id, HANDOFF_FROM_LEDGER, 10)
        .await
        .expect("cursor page");

    let page: Vec<&str> = page.iter().map(|e| e.id.as_str()).collect();
    let after_other: Vec<&str> = after_other.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(page, [first.id.as_str(), second.id.as_str()]);
    // The limit counts only the requested contract's events.
    let limited: Vec<&str> = limited.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(limited, [other.id.as_str()]);
    assert_eq!(cursor_ledger, Some(other.ledger));
    assert_eq!(after_other, [second.id.as_str()]);
}

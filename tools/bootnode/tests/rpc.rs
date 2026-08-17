mod common;

use bootnode::{
    messages::GetEventsParams,
    rpc::{RETENTION_HANDOFF_CODE, WARMING_UP_CODE},
};
use common::*;
use serde_json::json;

#[tokio::test]
async fn get_events_limit_1() {
    const PORT: u16 = 40404;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let first = sample_event_at(GENESIS_LEDGER + 1_000);
    let second = sample_event_at(GENESIS_LEDGER + 2_000);

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, &[first.clone(), second.clone()]).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // first page
    let first_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1),
    )
    .await;
    assert!(
        first_page.error.is_none(),
        "unexpected error: {:?}",
        first_page.error
    );
    let first_page = first_page.result.expect("first page");
    assert_eq!(first_page.events.len(), 1);
    assert_eq!(first_page.events[0].id, first.id);

    // second page
    let second_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&first_page.cursor), 1),
    )
    .await;

    assert!(
        second_page.error.is_none(),
        "unexpected error: {:?}",
        second_page.error
    );
    let second_page = second_page.result.expect("second page");
    assert_eq!(second_page.events.len(), 1);
    assert_eq!(second_page.events[0].id, second.id);

    // third page / handoff
    let third_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&second_page.cursor), 1),
    )
    .await;

    assert!(third_page.error.is_some(), "expected error",);
    assert_eq!(
        third_page.error.expect("expected error").code,
        i64::from(RETENTION_HANDOFF_CODE),
    );

    server.abort();
}

// TODO get events limit 2
// TODO get events no limit

#[tokio::test]
async fn get_events_skip_genesis() {
    const PORT: u16 = 40408;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let ledger = HANDOFF_FROM_LEDGER - 200;
    let event = sample_event_at(ledger);

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, std::slice::from_ref(&event)).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&event.id), 1000),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected handoff error");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
}

#[tokio::test]
async fn handoff_simple() {
    const PORT: u16 = 40405;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let ledger = HANDOFF_FROM_LEDGER + 100;
    let event = sample_event_at(ledger);

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, std::slice::from_ref(&event)).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // cursor request
    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&event.id), 1000),
    )
    .await;

    assert!(response.result.is_none());
    let err = response.error.expect("expected handoff error");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
    assert_eq!(
        err.data,
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": HANDOFF_FROM_LEDGER,
        }))
    );

    // start ledger request
    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(ledger), None, 1000),
    )
    .await;

    assert!(response.result.is_none());
    let err = response.error.expect("expected handoff error");
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

#[tokio::test]
async fn get_events_unknown_cursor_invalid_params() {
    const PORT: u16 = 40410;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some("unknown-event-id"), 1000),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected invalid params");
    assert_eq!(err.code, -32_602);
}

// TODO young pool deployment

#[tokio::test]
async fn warming_up_cold() {
    const PORT: u16 = 40407;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000);

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
    assert_eq!(err.code, i64::from(WARMING_UP_CODE));
    assert_eq!(err.message, "bootnode warming up; retry later");
}

#[tokio::test]
async fn warming_up_tip_known() {
    const PORT: u16 = 40409;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);
    seed_tip(&storage, NETWORK_TIP).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, 1000),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected warming-up error");
    assert_eq!(err.code, i64::from(WARMING_UP_CODE));
}

#[tokio::test]
async fn get_events_eventless() {
    const PORT: u16 = 40421;
    let base = format!("http://127.0.0.1:{PORT}");
    let start_ledger = GENESIS_LEDGER;

    let ids = contract_ids();
    let storage = test_storage(start_ledger);
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), start_ledger).await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

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
    let page = genesis.result.expect("empty genesis");
    assert!(page.events.is_empty());
    assert!(page.cursor.starts_with("bootnode:genesis:"));

    let handoff = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&page.cursor), 1000),
    )
    .await;

    server.abort();

    assert!(handoff.result.is_none());
    let err = handoff.error.expect("expected retention handoff");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
}

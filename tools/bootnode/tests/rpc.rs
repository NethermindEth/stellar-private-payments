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
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(1)),
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
        GetEventsParams::for_contracts(&ids, None, Some(&first_page.cursor), Some(1)),
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
        GetEventsParams::for_contracts(&ids, None, Some(&second_page.cursor), Some(1)),
    )
    .await;

    assert!(third_page.error.is_some(), "expected error",);
    assert_eq!(
        third_page.error.expect("expected error").code,
        i64::from(RETENTION_HANDOFF_CODE),
    );

    server.abort();
}

#[tokio::test]
async fn get_events_limit_2() {
    const PORT: u16 = 40406;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let events = [
        sample_event_at(GENESIS_LEDGER + 1_000),
        sample_event_at(GENESIS_LEDGER + 2_000),
        sample_event_at(GENESIS_LEDGER + 3_000),
        sample_event_at(GENESIS_LEDGER + 4_000),
    ];

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, events.as_slice()).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // first page
    let first_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(2)),
    )
    .await;
    assert!(
        first_page.error.is_none(),
        "unexpected error: {:?}",
        first_page.error
    );
    let first_page = first_page.result.expect("first page");
    assert_eq!(first_page.events.len(), 2);
    assert_eq!(first_page.events[0].id, events[0].id);
    assert_eq!(first_page.events[1].id, events[1].id);

    // second page
    let second_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&first_page.cursor), Some(2)),
    )
    .await;

    assert!(
        second_page.error.is_none(),
        "unexpected error: {:?}",
        second_page.error
    );
    let second_page = second_page.result.expect("second page");
    assert_eq!(second_page.events.len(), 2);
    assert_eq!(second_page.events[0].id, events[2].id);
    assert_eq!(second_page.events[1].id, events[3].id);

    // third page / handoff
    let third_page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&second_page.cursor), Some(2)),
    )
    .await;

    assert!(third_page.error.is_some(), "expected error",);
    assert_eq!(
        third_page.error.expect("expected error").code,
        i64::from(RETENTION_HANDOFF_CODE),
    );

    server.abort();
}

#[tokio::test]
async fn get_events_limit_1000() {
    const PORT: u16 = 40411;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let n_events = 10_000;
    let events = (0..n_events)
        .map(|i| sample_event_at(GENESIS_LEDGER + 10 + i / 2))
        .collect::<Vec<_>>();

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, events.as_slice()).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    // fetch loop
    let limit = 1000;
    let n_pages = n_events / limit;
    let page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(limit)),
    )
    .await;
    assert!(
        !page
            .result
            .as_ref()
            .expect("expected page")
            .events
            .is_empty()
    );
    let mut cursor = page.result.expect("expected page").cursor;
    for _ in 1..n_pages {
        let page = post_get_events(
            &client,
            &base,
            GetEventsParams::for_contracts(&ids, None, Some(&cursor), Some(limit)),
        )
        .await;
        assert!(
            !page
                .result
                .as_ref()
                .expect("expected page")
                .events
                .is_empty()
        );
        cursor = page.result.expect("expected page").cursor;
    }

    // last page / handoff
    let page = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, None, Some(&cursor), Some(limit)),
    )
    .await;

    assert!(page.error.is_some(), "expected error");
    assert_eq!(
        page.error.expect("expected error").code,
        i64::from(RETENTION_HANDOFF_CODE),
    );

    server.abort();
}

#[tokio::test]
async fn get_events_default_limit() {
    const PORT: u16 = 40423;
    let base = format!("http://127.0.0.1:{PORT}");
    const N_EVENTS: u32 = 1_001;

    let ids = contract_ids();
    let events: Vec<_> = (0..N_EVENTS)
        .map(|i| sample_event_at(GENESIS_LEDGER + i))
        .collect();

    let storage = test_storage(GENESIS_LEDGER);
    seed_events(&storage, &events).await;
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, None),
    )
    .await;

    server.abort();

    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    let page = response.result.expect("default-limit page");
    assert_eq!(page.events.len(), 1_000);
}

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
        GetEventsParams::for_contracts(&ids, None, Some(&event.id), Some(1000)),
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
        GetEventsParams::for_contracts(&ids, None, Some(&event.id), Some(1000)),
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
        GetEventsParams::for_contracts(&ids, Some(ledger), None, Some(1000)),
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
async fn handoff_recent_deployment() {
    const PORT: u16 = 40412;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let storage = test_storage(GENESIS_LEDGER);
    seed_tip(&storage, GENESIS_LEDGER + 100).await;

    let server = spawn_bootnode(
        storage,
        test_config(PORT, GENESIS_LEDGER + 100),
        GENESIS_LEDGER,
    )
    .await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(1000)),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected error");
    assert_eq!(err.code, i64::from(WARMING_UP_CODE));
}

#[tokio::test]
async fn get_events_unknown_cursor() {
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
        GetEventsParams::for_contracts(&ids, None, Some("unknown-event-id"), Some(1000)),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected invalid params");
    assert_eq!(err.code, -32_602);
}

#[tokio::test]
async fn warming_up_cold() {
    const PORT: u16 = 40407;
    let base = format!("http://127.0.0.1:{PORT}");

    let ids = contract_ids();
    let request = GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(1000));

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
        GetEventsParams::for_contracts(&ids, Some(GENESIS_LEDGER), None, Some(1000)),
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
        GetEventsParams::for_contracts(&ids, Some(start_ledger), None, Some(1000)),
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
        GetEventsParams::for_contracts(&ids, None, Some(&page.cursor), Some(1000)),
    )
    .await;

    server.abort();

    assert!(handoff.result.is_none());
    let err = handoff.error.expect("expected retention handoff");
    assert_eq!(err.code, i64::from(RETENTION_HANDOFF_CODE));
}

#[tokio::test]
async fn get_events_wrong_contract_id() {
    const PORT: u16 = 40422;
    let base = format!("http://127.0.0.1:{PORT}");

    let storage = test_storage(GENESIS_LEDGER);
    seed_tip(&storage, NETWORK_TIP).await;
    seed_archive_ready(&storage).await;

    let server = spawn_bootnode(storage, test_config(PORT, NETWORK_TIP), GENESIS_LEDGER).await;

    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;

    let response = post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(
            &["CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()],
            Some(GENESIS_LEDGER),
            None,
            Some(1000),
        ),
    )
    .await;

    server.abort();

    assert!(response.result.is_none());
    let err = response.error.expect("expected invalid params");
    assert_eq!(err.code, -32_602);
    assert_eq!(err.message, "unsupported filters");
}

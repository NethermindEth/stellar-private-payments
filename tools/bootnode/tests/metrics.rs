//! A test binary of its own: the recorder is process-global, and other tests'
//! requests would change the count.

mod common;

use bootnode::messages::GetEventsParams;
use common::*;

#[tokio::test]
async fn metrics_are_served_only_on_the_metrics_listener() {
    const PORT: u16 = 20426;
    const METRICS_PORT: u16 = 20427;
    let base = format!("http://127.0.0.1:{PORT}");

    let addr = format!("127.0.0.1:{METRICS_PORT}").parse().expect("addr");
    bootnode::metrics::serve(addr).await.expect("metrics");
    let taken = bootnode::metrics::serve(addr)
        .await
        .expect_err("port taken");
    let server = spawn_bootnode(
        test_storage(GENESIS_LEDGER),
        test_config(PORT, NETWORK_TIP),
        GENESIS_LEDGER,
    )
    .await;
    let client = reqwest::Client::new();
    wait_listening(&client, &base).await;
    post_get_events(
        &client,
        &base,
        GetEventsParams::for_contracts(&contract_ids(), Some(GENESIS_LEDGER), None, Some(1)),
    )
    .await;

    let public = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .expect("public");
    let metrics = client
        .get(format!("http://127.0.0.1:{METRICS_PORT}/metrics"))
        .send()
        .await
        .expect("metrics")
        .text()
        .await
        .expect("metrics body");

    server.abort();

    assert!(
        taken.to_string().starts_with("bind metrics listener"),
        "{taken:#}"
    );
    assert_eq!(public.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        metrics
            .lines()
            .any(|line| line == "bootnode_request_duration_seconds_count 1"),
        "{metrics}"
    );
}

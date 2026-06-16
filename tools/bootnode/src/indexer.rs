use crate::{AppState, deployment, storage};
use metrics::{counter, gauge};
use std::time::Instant;
use stellar::GetEventsParams;
use tokio::time::{Duration, sleep};

pub(crate) async fn run_indexer(state: AppState) {
    loop {
        if let Err(e) = run_round(&state).await {
            tracing::error!(error = %e, "indexer round failed");
            counter!("bootnode_indexer_round_errors_total").increment(1);
            sleep(Duration::from_millis(2_000)).await;
            continue;
        }
        sleep(Duration::from_millis(state.cfg.indexer_sleep_ms)).await;
    }
}

async fn run_round(state: &AppState) -> anyhow::Result<()> {
    let t0 = Instant::now();

    let latest = state.upstream.get_latest_ledger().await?;
    let tip_sequence = latest.sequence;
    state
        .ledger_tip
        .store(tip_sequence, std::sync::atomic::Ordering::Relaxed);
    gauge!("bootnode_ledger_tip").set(f64::from(tip_sequence));
    storage::update_ledger_tip(&state.db, tip_sequence).await?;

    let deployment = deployment::deployment_config()?;
    let contract_ids = stellar::contract_ids_for_indexer(&deployment);

    let kv = storage::load_kv(&state.db).await?;
    let mut cursor: Option<String> = kv.last_cursor;

    let mut start_ledger: Option<u32> = None;
    if cursor.is_none() {
        start_ledger = Some(stellar::min_pool_ledger_for_indexer(&deployment)?);
    }

    for _page in 0..state.cfg.max_pages_per_round {
        let params = GetEventsParams::for_contracts(
            &contract_ids,
            start_ledger,
            cursor.as_deref(),
            state.cfg.page_size,
        );
        let result = state.upstream.get_events(params.clone()).await?;

        let cursor_out = result.cursor.clone();
        let last_event_ledger = result.events.last().map(|event| event.ledger);

        storage::insert_get_events_page(
            &state.db,
            cursor.as_deref(),
            start_ledger,
            &params,
            &result,
            &cursor_out,
            last_event_ledger,
            result.latest_ledger,
            result.oldest_ledger,
        )
        .await?;

        storage::update_cursor(&state.db, &cursor_out).await?;

        cursor = Some(cursor_out);
        start_ledger = None;

        if result.events.is_empty() {
            if let Some(cursor) = cursor.as_deref() {
                storage::mark_caught_up(&state.db, cursor, result.latest_ledger).await?;
                gauge!("bootnode_last_fully_indexed_ledger").set(f64::from(result.latest_ledger));
            }
            break;
        }
    }

    counter!("bootnode_indexer_rounds_total").increment(1);
    metrics::histogram!("bootnode_indexer_round_duration_seconds")
        .record(t0.elapsed().as_secs_f64());

    Ok(())
}

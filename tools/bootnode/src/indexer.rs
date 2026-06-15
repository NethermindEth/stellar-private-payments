use crate::{AppState, deployment, get_events, jsonrpc, storage};
use metrics::{counter, gauge};
use serde_json::Value;
use std::time::Instant;
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

    // Update tip.
    let latest = state.upstream.get_latest_ledger().await?;
    let tip_sequence = u32::try_from(
        latest
            .get("sequence")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("upstream getLatestLedger missing sequence"))?,
    )
    .map_err(|_| anyhow::anyhow!("upstream getLatestLedger sequence exceeds u32"))?;
    state
        .tip_ledger
        .store(tip_sequence, std::sync::atomic::Ordering::Relaxed);
    gauge!("bootnode_tip_ledger").set(f64::from(tip_sequence));
    storage::update_tip(&state.db, tip_sequence).await?;

    let deployment = deployment::deployment_config()?;
    let contract_ids = stellar::contract_ids_for_indexer(&deployment);

    let kv = storage::load_kv(&state.db).await?;
    let mut cursor: Option<String> = kv.last_cursor;

    let mut start_ledger: Option<u32> = None;
    if cursor.is_none() {
        start_ledger = Some(stellar::min_pool_ledger_for_indexer(&deployment)?);
    }

    for _page in 0..state.cfg.max_pages_per_round {
        let params = jsonrpc::make_get_events_params(
            &contract_ids,
            start_ledger,
            cursor.as_deref(),
            state.cfg.page_size,
        );
        let result = state.upstream.get_events(params.clone()).await?;

        let (cursor_out, events, latest_ledger, oldest_ledger) =
            get_events::parse_get_events_result(&result)?;
        let last_event_ledger = events
            .last()
            .and_then(|e| e.get("ledger"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        storage::insert_get_events_page(
            &state.db,
            cursor.as_deref(),
            start_ledger,
            &params,
            &result,
            &cursor_out,
            last_event_ledger,
            latest_ledger,
            oldest_ledger,
        )
        .await?;

        storage::update_cursor(&state.db, &cursor_out).await?;

        cursor = Some(cursor_out);
        start_ledger = None;

        // Consider ourselves caught up when events are empty for the current cursor.
        if events.is_empty() {
            if let Some(cursor) = cursor.as_deref() {
                storage::mark_caught_up(&state.db, cursor, latest_ledger).await?;
                gauge!("bootnode_last_fully_indexed_ledger").set(f64::from(latest_ledger));
            }
            break;
        }
    }

    counter!("bootnode_indexer_rounds_total").increment(1);
    metrics::histogram!("bootnode_indexer_round_duration_seconds")
        .record(t0.elapsed().as_secs_f64());

    Ok(())
}

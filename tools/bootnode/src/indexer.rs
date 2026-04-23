use crate::{AppState, jsonrpc, storage};
use metrics::{counter, gauge};
use serde_json::Value;
use std::time::Instant;

pub(crate) async fn run_indexer(state: AppState) {
    loop {
        if let Err(e) = run_round(&state).await {
            tracing::error!(error = %e, "indexer round failed");
            counter!("bootnode_indexer_round_errors_total").increment(1);
            tokio::time::sleep(std::time::Duration::from_millis(2_000)).await;
            continue;
        }
        tokio::time::sleep(std::time::Duration::from_millis(state.cfg.indexer_sleep_ms)).await;
    }
}

async fn run_round(state: &AppState) -> anyhow::Result<()> {
    let t0 = Instant::now();

    // Update tip.
    let latest = state.upstream.get_latest_ledger().await?;
    let tip_sequence = latest
        .get("sequence")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("upstream getLatestLedger missing sequence"))? as u32;
    state.tip_ledger.store(tip_sequence, std::sync::atomic::Ordering::Relaxed);
    gauge!("bootnode_tip_ledger").set(tip_sequence as f64);
    storage::update_tip(&state.db, tip_sequence).await?;

    let deployment = stellar::deployment_config()?;
    let contract_ids = vec![deployment.pool, deployment.asp_membership];

    let kv = storage::load_kv(&state.db).await?;
    let mut cursor: Option<String> = kv.last_cursor;

    let mut start_ledger: Option<u32> = None;
    if cursor.is_none() {
        start_ledger = Some(deployment.deployment_ledger);
    }

    for _page in 0..state.cfg.max_pages_per_round {
        let params = jsonrpc::make_get_events_params(
            &contract_ids,
            start_ledger,
            cursor.as_deref(),
            state.cfg.page_size,
        );
        let result = state.upstream.get_events(params.clone()).await?;

        let (cursor_out, events, latest_ledger, oldest_ledger) = parse_get_events_result(&result)?;
        let last_event_ledger = events
            .last()
            .and_then(|e| e.get("ledger"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

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
                gauge!("bootnode_last_fully_indexed_ledger").set(latest_ledger as f64);
            }
            break;
        }
    }

    counter!("bootnode_indexer_rounds_total").increment(1);
    metrics::histogram!("bootnode_indexer_round_duration_seconds").record(t0.elapsed().as_secs_f64());

    Ok(())
}

fn parse_get_events_result(
    result: &Value,
) -> anyhow::Result<(String, Vec<Value>, u32, u32)> {
    let cursor = result
        .get("cursor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing cursor"))?
        .to_string();
    let events = result
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing events"))?
        .clone();
    let latest_ledger = result
        .get("latestLedger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing latestLedger"))? as u32;
    let oldest_ledger = result
        .get("oldestLedger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing oldestLedger"))? as u32;
    Ok((cursor, events, latest_ledger, oldest_ledger))
}


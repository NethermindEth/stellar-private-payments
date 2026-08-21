use crate::{AppState, messages::GetEventsParams};
use metrics::{counter, gauge};
use std::{sync::atomic::Ordering, time::Instant};
use tokio::time::{Duration, sleep};

pub(crate) struct Indexer {
    state: AppState,
}

impl Indexer {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }

    pub(crate) async fn run(self) {
        loop {
            match self.run_round().await {
                Ok(may_have_more) => {
                    if !may_have_more {
                        sleep(Duration::from_millis(self.state.cfg.indexer_sleep_ms)).await;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "indexer round failed");
                    counter!("bootnode_indexer_round_errors_total").increment(1);
                    sleep(Duration::from_millis(2_000)).await;
                }
            }
        }
    }

    async fn run_round(&self) -> anyhow::Result<bool> {
        let t0 = Instant::now();

        let latest = self.state.upstream.get_latest_ledger().await?;
        let tip_sequence = latest.sequence;
        self.state.ledger_tip.store(tip_sequence, Ordering::Relaxed);
        gauge!("bootnode_ledger_tip").set(f64::from(tip_sequence));
        self.state.storage.set_ledger_tip(tip_sequence).await?;

        let indexer = self.state.storage.load_indexer_state().await?;
        let mut cursor = indexer.last_upstream_cursor;
        let mut start_ledger = cursor.is_none().then_some(self.state.min_deployment_ledger);
        let page_size = self.state.cfg.page_size;
        let mut may_have_more = false;
        let cutoff = tip_sequence.saturating_sub(self.state.cfg.cutoff_ledgers());

        for _page in 0..self.state.cfg.max_pages_per_round {
            let prev_cursor = cursor.clone();
            let params = GetEventsParams::for_contracts(
                self.state.contract_ids.as_ref(),
                start_ledger,
                cursor.as_deref(),
                Some(page_size),
            );
            let result = self.state.upstream.get_events(params).await?;

            self.state.storage.upsert_events(&result.events).await?;
            if result.oldest_ledger > 0 {
                self.state
                    .storage
                    .set_oldest_ledger(result.oldest_ledger)
                    .await?;
                self.state
                    .oldest_ledger
                    .store(result.oldest_ledger, Ordering::Relaxed);
            }

            let cursor_out = result.cursor.clone();
            let cursor_advanced = prev_cursor.as_deref() != Some(cursor_out.as_str());
            let at_upstream_tail = prev_cursor.is_some() && !cursor_advanced;
            let progress_ledger = if result.events.is_empty() {
                result.latest_ledger
            } else {
                result
                    .events
                    .last()
                    .map(|event| event.ledger)
                    .unwrap_or(result.latest_ledger)
            };

            self.state
                .storage
                .set_last_upstream_cursor(&cursor_out)
                .await?;

            cursor = Some(cursor_out);
            start_ledger = None;

            if !self.state.archive_ready.load(Ordering::Relaxed)
                && at_upstream_tail
                && progress_ledger >= cutoff
            {
                self.mark_archive_ready().await?;
            }

            if at_upstream_tail {
                may_have_more = false;
                break;
            }

            may_have_more = true;
        }

        counter!("bootnode_indexer_rounds_total").increment(1);
        metrics::histogram!("bootnode_indexer_round_duration_seconds")
            .record(t0.elapsed().as_secs_f64());

        Ok(may_have_more)
    }

    async fn mark_archive_ready(&self) -> anyhow::Result<()> {
        if self.state.archive_ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.state.storage.set_archive_ready().await?;
        self.state.archive_ready.store(true, Ordering::Relaxed);
        tracing::info!("archive ready: ingestion crossed retention cutoff");
        Ok(())
    }
}

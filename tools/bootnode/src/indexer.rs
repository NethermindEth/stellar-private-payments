use crate::{AppState, messages::GetEventsParams, storage::InsertGetEventsPage};
use metrics::{counter, gauge};
use std::time::Instant;
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

    /// Fetch up to `max_pages_per_round` event pages from upstream.
    ///
    /// Returns `true` when another round may be needed (page budget exhausted
    /// while still behind tip). Returns `false` when caught up for now.
    async fn run_round(&self) -> anyhow::Result<bool> {
        let t0 = Instant::now();

        let latest = self.state.upstream.get_latest_ledger().await?;
        let tip_sequence = latest.sequence;
        self.state
            .ledger_tip
            .store(tip_sequence, std::sync::atomic::Ordering::Relaxed);
        gauge!("bootnode_ledger_tip").set(f64::from(tip_sequence));
        self.state.storage.set_ledger_tip(tip_sequence).await?;

        let kv = self.state.storage.load_kv().await?;
        let mut cursor = kv.last_cursor;

        let mut start_ledger = cursor.is_none().then_some(self.state.min_deployment_ledger);
        let page_size = self.state.cfg.page_size;
        let mut may_have_more = false;

        for _page in 0..self.state.cfg.max_pages_per_round {
            let params = GetEventsParams::for_contracts(
                self.state.contract_ids.as_ref(),
                start_ledger,
                cursor.as_deref(),
                page_size,
            );
            let result = self.state.upstream.get_events(params.clone()).await?;

            let cursor_out = result.cursor.clone();
            let last_event_ledger = result.events.last().map(|event| event.ledger);
            let event_count = result.events.len();
            let is_empty = event_count == 0;
            let full_page = event_count == page_size as usize;
            let progress_ledger = last_event_ledger.unwrap_or(result.latest_ledger);
            let at_events_tip = !is_empty && !full_page && progress_ledger >= result.latest_ledger;
            let fully_indexed = is_empty || at_events_tip;

            if !is_empty {
                self.state.storage.set_in_sync(false).await?;
                self.state
                    .storage
                    .insert_get_events_page(InsertGetEventsPage {
                        cursor_in: cursor.as_deref(),
                        start_ledger,
                        request: &params,
                        result: &result,
                        cursor_out: &cursor_out,
                        last_event_ledger,
                        latest_ledger: result.latest_ledger,
                        oldest_ledger: result.oldest_ledger,
                    })
                    .await?;
            }

            cursor = Some(cursor_out);
            start_ledger = None;

            if fully_indexed {
                self.state
                    .storage
                    .mark_caught_up(cursor.as_deref().expect("cursor set"), result.latest_ledger)
                    .await?;
                gauge!("bootnode_last_fully_indexed_ledger").set(f64::from(result.latest_ledger));
                may_have_more = false;
                break;
            }

            self.state
                .storage
                .update_cursor(cursor.as_deref().expect("cursor set"))
                .await?;
            may_have_more = true;
        }

        counter!("bootnode_indexer_rounds_total").increment(1);
        metrics::histogram!("bootnode_indexer_round_duration_seconds")
            .record(t0.elapsed().as_secs_f64());

        Ok(may_have_more)
    }
}

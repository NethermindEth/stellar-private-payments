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
        let mut rescan_from = self.state.cfg.rescan_from;
        loop {
            let round = self.run_round(rescan_from).await;
            rescan_from = rescan_after(rescan_from, &round);
            match round {
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

    async fn run_round(&self, rescan_from: Option<u32>) -> anyhow::Result<bool> {
        let t0 = Instant::now();

        let latest = self.state.upstream.get_latest_ledger().await?;
        let tip_sequence = latest.sequence;
        self.state.ledger_tip.store(tip_sequence, Ordering::Relaxed);
        gauge!("bootnode_ledger_tip").set(f64::from(tip_sequence));
        self.state.storage.set_ledger_tip(tip_sequence).await?;

        let indexer = self.state.storage.load_indexer_state().await?;
        let (mut cursor, mut start_ledger) = round_start(
            indexer.last_upstream_cursor,
            rescan_from,
            self.state.min_deployment_ledger,
        );
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

/// Returns the cursor and start ledger a round's first request uses.
///
/// A rescan ledger replaces the stored cursor. With no stored cursor, the
/// round starts at the earlier of the rescan ledger and the deployment's
/// minimum, so an empty archive still fills from the start.
fn round_start(
    stored_cursor: Option<String>,
    rescan_from: Option<u32>,
    min_deployment_ledger: u32,
) -> (Option<String>, Option<u32>) {
    match (rescan_from, stored_cursor) {
        (Some(ledger), Some(_)) => (None, Some(ledger)),
        (Some(ledger), None) => (None, Some(ledger.min(min_deployment_ledger))),
        (None, Some(cursor)) => (Some(cursor), None),
        (None, None) => (None, Some(min_deployment_ledger)),
    }
}

/// Returns the rescan ledger for the round after `round`.
///
/// The rescan ends after the first successful round; a failed round keeps it
/// for the retry.
fn rescan_after(rescan_from: Option<u32>, round: &anyhow::Result<bool>) -> Option<u32> {
    rescan_from.filter(|_| round.is_err())
}

#[cfg(test)]
mod tests {
    use super::{rescan_after, round_start};

    #[test]
    fn a_rescan_starts_the_first_round_at_its_ledger() {
        assert_eq!(
            round_start(Some("cursor".into()), Some(500), 100),
            (None, Some(500))
        );
    }

    #[test]
    fn without_a_rescan_the_stored_cursor_wins() {
        assert_eq!(
            round_start(Some("cursor".into()), None, 100),
            (Some("cursor".into()), None)
        );
    }

    #[test]
    fn a_rescan_ends_with_the_first_round_that_succeeds() {
        let failed: anyhow::Result<bool> = Err(anyhow::anyhow!("upstream unavailable"));
        assert_eq!(rescan_after(Some(500), &failed), Some(500));

        let next = rescan_after(Some(500), &Ok(true));
        assert_eq!(
            round_start(Some("cursor".into()), next, 100),
            (Some("cursor".into()), None)
        );
    }

    #[test]
    fn an_empty_archive_starts_at_the_deployment() {
        assert_eq!(round_start(None, None, 100), (None, Some(100)));
        assert_eq!(round_start(None, Some(500), 100), (None, Some(100)));
    }
}

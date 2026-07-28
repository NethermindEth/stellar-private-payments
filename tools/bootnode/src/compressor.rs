use crate::{AppState, config::ledgers_per_day};
use metrics::counter;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, sleep};

/// Periodically collapses recent empty `getEvents` pages once the indexer is
/// at tip (handoff-window / tip-suffix policy in `storage::compress`).
///
/// Cadence is one ledger-day (`86400 / ledger_seconds`).
pub(crate) struct EmptyPageCompressor {
    state: AppState,
}

impl EmptyPageCompressor {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }

    pub(crate) async fn run(self) {
        // Check often enough to notice tip/day advances; work itself is cheap
        // when there is nothing to do.
        let poll = Duration::from_secs(60);
        loop {
            if let Err(e) = self.tick().await {
                tracing::error!(error = %e, "empty page compressor tick failed");
                counter!("bootnode_compressor_errors_total").increment(1);
            }
            sleep(poll).await;
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        if !self.state.in_sync.load(Ordering::Relaxed) {
            return Ok(());
        }

        let kv = self.state.storage.load_kv().await?;
        let tip = self
            .state
            .ledger_tip
            .load(Ordering::Relaxed)
            .max(kv.ledger_tip);
        let day = ledgers_per_day(self.state.cfg.ledger_seconds);
        let through_ledger = tip.saturating_sub(day);
        if through_ledger == 0 {
            return Ok(());
        }
        if kv.last_empty_compress_ledger >= through_ledger {
            return Ok(());
        }

        let cutoff_ledger = tip.saturating_sub(self.state.cfg.cutoff_ledgers());
        let stats = self
            .state
            .storage
            .compress_empty_pages(cutoff_ledger)
            .await?;
        self.state
            .storage
            .set_last_empty_compress_ledger(through_ledger)
            .await?;

        if stats.pages_removed > 0 {
            tracing::info!(
                cutoff_ledger,
                through_ledger,
                tip,
                spans_joined = stats.spans_joined,
                pages_removed = stats.pages_removed,
                "compressed empty getEvents pages in handoff window"
            );
            counter!("bootnode_compressor_pages_removed_total")
                .increment(u64::from(stats.pages_removed));
            counter!("bootnode_compressor_spans_joined_total")
                .increment(u64::from(stats.spans_joined));
        } else {
            tracing::debug!(
                cutoff_ledger,
                through_ledger,
                tip,
                "empty page compressor: nothing to join"
            );
        }

        Ok(())
    }
}

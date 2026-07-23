use crate::rpc::{Client, Error as RpcError};
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use types::{ContractConfig, ContractsEventData, SyncMetadata};

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const PAGE_SIZE: usize = 1000;
const MAX_PAGES_PER_ROUND: usize = 10;

pub struct Indexer<S: ContractDataStorage> {
    client: Client,
    storage: S,
    contract_ids: Vec<String>,
    min_pool_ledger: u32,
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(client: Client, storage: S, config: &ContractConfig) -> Result<Self> {
        let min_pool_ledger = config.min_deployment_ledger()?;
        let contract_ids = config.all_contract_ids();

        let existing_sync = storage.get_sync_state().await?;
        let active_contract_ids: HashSet<&str> = contract_ids.iter().map(String::as_str).collect();
        let active_sync: Vec<_> = existing_sync
            .into_iter()
            .filter(|meta| active_contract_ids.contains(meta.contract_id.as_str()))
            .collect();

        let probe_ledger = active_sync
            .iter()
            .map(|meta| meta.last_indexed_ledger)
            .filter(|ledger| *ledger > 0)
            .min()
            .unwrap_or(min_pool_ledger);

        match client
            .get_contract_events(&contract_ids, probe_ledger, 1, None)
            .await
        {
            Ok(_) => {}
            Err(RpcError::RpcSyncGap(oldest)) => {
                return Err(RpcError::RpcSyncGap(oldest).into());
            }
            // The probe ledger is at/ahead of the RPC's events tip: we are
            // already caught up, which is not a retention gap. Proceed; the
            // fetch loop will idle until the RPC indexes further.
            Err(RpcError::RpcAhead(_)) => {}
            Err(e) => return Err(e.into()),
        }

        Ok(Self {
            client,
            storage,
            contract_ids,
            min_pool_ledger,
        })
    }

    /// Fetch up to [`MAX_PAGES_PER_ROUND`] event pages from RPC into storage.
    ///
    /// Returns `true` when another round may be needed. Returns `false` when
    /// caught up for now:
    /// - empty page (best-effort; sparse RPC scans can also be empty),
    /// - non-full page with `max(event.ledger) >= latestLedger`, or
    /// - local sync ahead of the RPC events tip (`RpcAhead`).
    ///
    /// A full page (`PAGE_SIZE` events) always continues, even at the tip
    /// ledger, because more events may share that ledger.
    pub async fn fetch_contract_events(&self) -> Result<bool> {
        let network_tip = self.client.get_latest_ledger().await?.sequence;
        let existing_sync = self.storage.get_sync_state().await?;
        let active_contract_ids: HashSet<&str> =
            self.contract_ids.iter().map(String::as_str).collect();
        let active_sync: Vec<_> = existing_sync
            .into_iter()
            .filter(|meta| active_contract_ids.contains(meta.contract_id.as_str()))
            .collect();

        let start_ledger = active_sync
            .iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(self.min_pool_ledger)
            .min(network_tip);

        if active_sync
            .iter()
            .map(|meta| meta.last_indexed_ledger)
            .collect::<HashSet<_>>()
            .len()
            > 1
        {
            log::warn!(
                "[INDEXER] sync ledger divergence detected for {} active contracts; using min last_indexed_ledger={start_ledger}",
                active_sync.len()
            );
        }

        let unique_cursors: HashSet<&str> = active_sync
            .iter()
            .filter_map(|meta| (!meta.cursor.is_empty()).then_some(meta.cursor.as_str()))
            .collect();
        let mut cursor = if unique_cursors.len() <= 1 {
            active_sync
                .first()
                .and_then(|meta| (!meta.cursor.is_empty()).then(|| meta.cursor.clone()))
        } else {
            log::warn!(
                "[INDEXER] sync cursor divergence detected for {} active contracts; resetting cursor and replaying from ledger={start_ledger}",
                active_sync.len()
            );
            None
        };

        let mut may_have_more = false;

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );

            let (new_cursor, events, latest_ledger) = match self
                .client
                .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, cursor)
                .await
            {
                Ok(page) => page,
                // We are ahead of the RPC's events tip: nothing to fetch until
                // it indexes further. Idle this round instead of erroring.
                Err(RpcError::RpcAhead(newest)) => {
                    log::debug!(
                        "[INDEXER] local sync (start_ledger={start_ledger}) is ahead of RPC events tip (newest={newest}); waiting for RPC to catch up"
                    );
                    return Ok(false);
                }
                Err(e) => return Err(e.into()),
            };

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let event_count = events.len();
            let is_empty = event_count == 0;
            let full_page = event_count == PAGE_SIZE;
            let progress_ledger = if is_empty {
                latest_ledger
            } else {
                events
                    .iter()
                    .map(|event| event.ledger)
                    .max()
                    .unwrap_or(latest_ledger)
            };
            // Non-full page whose newest event is at/past the RPC events tip.
            let at_events_tip = !is_empty && !full_page && progress_ledger >= latest_ledger;
            let fully_indexed = is_empty || at_events_tip;

            self.storage
                .save_events_batch(ContractsEventData {
                    cursor: new_cursor.clone(),
                    latest_ledger,
                    events: events.into_iter().map(|e| e.into()).collect(),
                })
                .await?;

            self.storage
                .save_sync_progress(
                    self.contract_ids
                        .iter()
                        .map(|contract_id| SyncMetadata {
                            contract_id: contract_id.clone(),
                            cursor: new_cursor.clone(),
                            last_indexed_ledger: progress_ledger,
                            last_fully_indexed_ledger: 0,
                        })
                        .collect(),
                    fully_indexed,
                )
                .await?;

            cursor = Some(new_cursor);
            if fully_indexed {
                return Ok(false);
            }
            // Full page, or partial page still behind latestLedger: keep going.
            may_have_more = true;
        }

        Ok(may_have_more)
    }
}

#[async_trait::async_trait(?Send)]
pub trait ContractDataStorage {
    /// Gets the last synced ledger and cursor for all contracts.
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>>;

    /// Sends a batch of events to be saved and waits for confirmation.
    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()>;

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()>;
}

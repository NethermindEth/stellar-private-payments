use crate::rpc::{Client, Error as RpcError};
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const PAGE_SIZE: usize = 300;
const MAX_PAGES_PER_ROUND: usize = 10;

pub struct Indexer<S: ContractDataStorage> {
    client: Client,
    storage: S,
    contract_ids: Vec<String>,
    min_pool_ledger: u32,
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(rpc_url: &str, storage: S, config: &'static ContractConfig) -> Result<Self> {
        let client = Client::new(rpc_url)?;
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

    pub async fn fetch_contract_events(&self) -> Result<()> {
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
            .unwrap_or(self.min_pool_ledger);

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
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let is_empty = events.is_empty();
            let progress_ledger = if is_empty {
                latest_ledger
            } else {
                events
                    .iter()
                    .map(|event| event.ledger)
                    .max()
                    .unwrap_or(latest_ledger)
            };

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
                    is_empty,
                )
                .await?;

            cursor = Some(new_cursor);
            if is_empty {
                break;
            }
        }

        Ok(())
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
impl From<crate::rpc::Event> for ContractEvent {
    fn from(val: crate::rpc::Event) -> Self {
        let crate::rpc::Event {
            id,
            ledger,
            contract_id,
            topic,
            value,
            ..
        } = val;
        ContractEvent {
            id,
            ledger,
            contract_id,
            topics: topic,
            value,
        }
    }
}

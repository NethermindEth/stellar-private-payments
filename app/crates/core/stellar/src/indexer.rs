use crate::rpc::Client;
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
    min_deployment_ledger: u32,
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(rpc_url: &str, storage: S, config: &'static ContractConfig) -> Result<Self> {
        Ok(Self {
            client: Client::new(rpc_url)?,
            storage,
            contract_ids: config.pools_and_membership_contract_ids(),
            min_deployment_ledger: config.min_deployment_ledger()?,
        })
    }

    /// Fetch and persist contract events.
    ///
    /// When `start_ledger_override` is `Some`, paging begins at that ledger
    /// with no cursor.
    pub async fn fetch_contract_events(&self, start_ledger_override: Option<u32>) -> Result<()> {
        let network_tip = self.client.get_latest_ledger().await?.sequence;
        let existing_sync = self.storage.get_sync_state().await?;
        let active_contract_ids: HashSet<&str> =
            self.contract_ids.iter().map(String::as_str).collect();
        let active_sync: Vec<_> = existing_sync
            .into_iter()
            .filter(|meta| active_contract_ids.contains(meta.contract_id.as_str()))
            .collect();

        let start_ledger = start_ledger_override.unwrap_or_else(|| {
            active_sync
                .iter()
                .map(|meta| meta.last_ledger)
                .min()
                .unwrap_or(self.min_deployment_ledger)
        });

        if start_ledger_override.is_none()
            && active_sync
                .iter()
                .map(|meta| meta.last_ledger)
                .collect::<HashSet<_>>()
                .len()
                > 1
        {
            log::warn!(
                "[INDEXER] sync ledger divergence detected for {} active contracts; using min last_ledger={start_ledger}",
                active_sync.len()
            );
        }

        let mut cursor = if start_ledger_override.is_some() {
            None
        } else {
            let unique_cursors: HashSet<&str> = active_sync
                .iter()
                .map(|meta| meta.cursor.as_str())
                .collect();
            if unique_cursors.len() <= 1 {
                active_sync.first().map(|meta| meta.cursor.clone())
            } else {
                log::warn!(
                    "[INDEXER] sync cursor divergence detected for {} active contracts; resetting cursor and replaying from ledger={start_ledger}",
                    active_sync.len()
                );
                None
            }
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );

            let (new_cursor, events, latest_ledger) = self
                .client
                .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, cursor.clone())
                .await?;

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let is_empty = events.is_empty();

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
                            last_ledger: latest_ledger,
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

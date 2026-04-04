use anyhow::{anyhow, Result};
use crate::rpc::Client;
use crate::DEPLOYMENT;
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

const PAGE_SIZE: usize = 300;
const LEDGERS_7DAYS: u32 = 7 * 24 * 60 * 60 / 5;

pub struct Indexer<S: ContractDataStorage> {
    client: Client,
    config: ContractConfig,
    storage: S,
}

impl<S: ContractDataStorage> Indexer<S> {

    pub fn new(rpc_url: &str, storage: S) -> Result<Self> {
        let config: ContractConfig = serde_json::from_str(DEPLOYMENT)?;
        Ok(Self {
            client: Client::new(rpc_url)?,
            config,
            storage
        })
    }

    pub async fn fetch_contract_events(
        &self
    ) -> Result<()> {
        let contract_ids = [self.config.pool.to_string(), self.config.asp_membership.to_string(), self.config.asp_non_membership.to_string()];
        let network_tip = self.client.get_latest_ledger().await?.sequence;
        log::debug!("[INDEXER] starting new round for network tip {network_tip}, contract ids {contract_ids:?}");
        let (mut cursor, mut current_ledger) = if let Some(SyncMetadata {cursor, last_ledger}) = self.storage.get_sync_state().await? {
            (Some(cursor), last_ledger)
        } else {
            log::debug!("[INDEXER] no saved sync metadata - the current round starts at the current network tip {network_tip}");
            let start_seven_days_ago = network_tip;
            (None, start_seven_days_ago)
        };
        while current_ledger < network_tip {
            log::debug!("[INDEXER] current_ledger {current_ledger}, cursor {cursor:?}");
            let (new_cursor, events, _) = self.client.get_contract_events(
                &contract_ids,
                current_ledger,
                PAGE_SIZE,
                cursor
                ).await?;

            if let Some(last_event) = events.last() {
                // TODO check they ordered by time
                log::debug!("[INDEXER] fetched {} events", events.len());
                current_ledger = last_event.ledger;
                self.storage.save_events_batch(ContractsEventData{cursor: new_cursor.clone().ok_or_else(|| anyhow!("cursor is not found in the events response"))?,
                    events: events.into_iter().map(|e| e.into()).collect()} ).await?;
            } else {
                current_ledger += 1;
            }
            cursor = new_cursor;
        }

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
pub trait ContractDataStorage {
    /// Gets the last synced ledger and cursor from the store
    async fn get_sync_state(&self) -> anyhow::Result<Option<SyncMetadata>>;

    /// Sends a batch of events to be saved and waits for confirmation
    async fn save_events_batch(
        &self,
        batch: ContractsEventData
    ) -> anyhow::Result<()>;
}

impl Into<ContractEvent> for crate::rpc::Event {

    fn into(self) -> ContractEvent {
        let crate::rpc::Event {
            id,
            ledger,
            contract_id,
            topic,
            value,
            ..
        } = self;
        ContractEvent {
            id,
            ledger,
            contract_id,
            topics: topic,
            value,
            }
    }
}

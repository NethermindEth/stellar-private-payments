//! Synchronous contract-event indexer backed by local [`Storage`].

use std::collections::HashSet;

use crate::runtime::block_on_rpc;
use anyhow::{Result, anyhow};
use state::Storage;
use stellar::{Client, Event};
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

const PAGE_SIZE: usize = 300;
const MAX_PAGES_PER_ROUND: usize = 10;

/// Fetches pool and ASP membership events from RPC into local SQLite.
pub struct Indexer {
    client: Client,
    storage: Storage,
    contract_ids: Vec<String>,
    min_pool_ledger: u32,
}

impl Indexer {
    pub fn open(storage_path: &str, rpc_url: &str, config: &ContractConfig) -> Result<Self> {
        let storage = Storage::connect_file(storage_path)?;
        let client = Client::new(rpc_url)?;
        let min_pool_ledger = config.min_deployment_ledger()?;
        let contract_ids = config.pools_and_membership_contract_ids();

        Ok(Self {
            client,
            storage,
            contract_ids,
            min_pool_ledger,
        })
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }

    /// Fetch up to [`MAX_PAGES_PER_ROUND`] event pages from RPC into storage.
    ///
    /// Returns `true` when the round ended on a non-empty page (caller may want
    /// another round).
    pub fn fetch_contract_events(&mut self) -> Result<bool> {
        let network_tip = block_on_rpc(self.client.get_latest_ledger())?.sequence;
        let existing_sync = self.storage.get_sync_metadata()?;
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

        let mut may_have_more = false;

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );

            let (new_cursor, events, latest_ledger) =
                block_on_rpc(self.client.get_contract_events(
                    &self.contract_ids,
                    start_ledger,
                    PAGE_SIZE,
                    cursor.clone(),
                ))?;

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

            self.storage.save_events_batch(&ContractsEventData {
                cursor: new_cursor.clone(),
                latest_ledger,
                events: events.into_iter().map(contract_event_from_rpc).collect(),
            })?;

            self.storage.save_sync_progress(
                &self
                    .contract_ids
                    .iter()
                    .map(|contract_id| SyncMetadata {
                        contract_id: contract_id.clone(),
                        cursor: new_cursor.clone(),
                        last_indexed_ledger: progress_ledger,
                        last_fully_indexed_ledger: 0,
                    })
                    .collect::<Vec<_>>(),
                is_empty,
            )?;

            cursor = Some(new_cursor);
            if is_empty {
                return Ok(may_have_more);
            }
            may_have_more = true;
        }

        Ok(may_have_more)
    }
}

fn contract_event_from_rpc(event: Event) -> ContractEvent {
    ContractEvent {
        id: event.id,
        ledger: event.ledger,
        contract_id: event.contract_id,
        topics: event.topic,
        value: event.value,
    }
}

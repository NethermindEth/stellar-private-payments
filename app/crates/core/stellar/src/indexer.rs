use crate::rpc::{Client, Error as RpcError};
use anyhow::{Result, anyhow};
use std::{cell::Cell, collections::HashSet};
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const PAGE_SIZE: usize = 300;
const MAX_PAGES_PER_ROUND: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncPhase {
    Rpc,
    Bootnode,
}

pub struct Indexer<S: ContractDataStorage> {
    rpc: Client,
    bootnode: Option<Client>,
    phase: Cell<SyncPhase>,
    storage: S,
    contract_ids: Vec<String>,
    min_pool_ledger: u32,
}

/// Contract IDs indexed by the app (enabled pools + ASP membership).
pub fn contract_ids_for_indexer(config: &ContractConfig) -> Vec<String> {
    config
        .pools
        .iter()
        .filter_map(|p| p.enabled.then_some(p.pool_contract_id.clone()))
        .chain(std::iter::once(config.asp_membership.clone()))
        .collect()
}

/// Earliest deployment ledger among enabled pools.
pub fn min_pool_ledger_for_indexer(config: &ContractConfig) -> Result<u32> {
    config
        .pools
        .iter()
        .filter(|p| p.enabled)
        .map(|p| p.deployment_ledger)
        .min()
        .ok_or_else(|| anyhow!("at least one pool should be enabled"))
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(
        rpc_url: &str,
        bootnode_url: Option<&str>,
        storage: S,
        config: &'static ContractConfig,
    ) -> Result<Self> {
        let rpc = Client::new(rpc_url)?;
        let min_pool_ledger = min_pool_ledger_for_indexer(config)?;
        let contract_ids = contract_ids_for_indexer(config);

        match rpc
            .get_contract_events(&contract_ids, min_pool_ledger, 1, None)
            .await
        {
            Ok(_) => Ok(Self {
                rpc,
                bootnode: None,
                phase: Cell::new(SyncPhase::Rpc),
                storage,
                contract_ids,
                min_pool_ledger,
            }),
            Err(RpcError::RpcSyncGap(oldest)) => {
                let Some(bootnode_url) = bootnode_url else {
                    return Err(anyhow!(
                        "RPC_SYNC_GAP oldest={oldest} deployment={0} rpc={rpc_url}\n\
Your RPC node {rpc_url} oldest available ledger is {oldest}. \
Indexing requires events back to the pool deployment ledger {0}. \
Please use a fresher contracts deployment / a different RPC which stores events up to ledger {0}.",
                        min_pool_ledger
                    ));
                };
                let bootnode = Client::new(bootnode_url)?;
                bootnode
                    .get_contract_events(&contract_ids, min_pool_ledger, 1, None)
                    .await?;
                Ok(Self {
                    rpc,
                    bootnode: Some(bootnode),
                    phase: Cell::new(SyncPhase::Bootnode),
                    storage,
                    contract_ids,
                    min_pool_ledger,
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    fn events_client(&self) -> &Client {
        match self.phase.get() {
            SyncPhase::Bootnode => self
                .bootnode
                .as_ref()
                .expect("bootnode phase requires bootnode client"),
            SyncPhase::Rpc => &self.rpc,
        }
    }

    pub async fn fetch_contract_events(&self) -> Result<()> {
        let network_tip = self.events_client().get_latest_ledger().await?.sequence;
        let existing_sync = self.storage.get_sync_state().await?;
        let active_contract_ids: HashSet<&str> =
            self.contract_ids.iter().map(String::as_str).collect();
        let active_sync: Vec<_> = existing_sync
            .into_iter()
            .filter(|meta| active_contract_ids.contains(meta.contract_id.as_str()))
            .collect();

        let mut start_ledger = active_sync
            .iter()
            .map(|meta| meta.last_ledger)
            .min()
            .unwrap_or(self.min_pool_ledger);

        if active_sync
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

        let unique_cursors: HashSet<&str> = active_sync
            .iter()
            .map(|meta| meta.cursor.as_str())
            .collect();
        let mut cursor = if unique_cursors.len() <= 1 {
            active_sync.first().map(|meta| meta.cursor.clone())
        } else {
            log::warn!(
                "[INDEXER] sync cursor divergence detected for {} active contracts; resetting cursor and replaying from ledger={start_ledger}",
                active_sync.len()
            );
            None
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}, phase={:?}",
                self.phase.get()
            );

            let (new_cursor, events, latest_ledger) = match self
                .events_client()
                .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, cursor.clone())
                .await
            {
                Err(RpcError::RetentionHandoff { from_ledger }) => {
                    if self.phase.get() != SyncPhase::Bootnode {
                        return Err(anyhow!(
                            "unexpected bootnode handoff at ledger {from_ledger}"
                        ));
                    }
                    log::info!(
                        "[INDEXER] bootnode archive complete at ledger {from_ledger}, resuming on main RPC"
                    );
                    self.phase.set(SyncPhase::Rpc);
                    start_ledger = from_ledger;
                    self.rpc
                        .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, None)
                        .await?
                }
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            };

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

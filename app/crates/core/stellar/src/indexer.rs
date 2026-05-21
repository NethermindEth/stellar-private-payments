use crate::{
    DEPLOYMENT,
    rpc::{Client, Error as RpcError},
};
use anyhow::{Result, anyhow};
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

const PAGE_SIZE: usize = 300;
const MAX_PAGES_PER_ROUND: usize = 10;

pub struct Indexer<S: ContractDataStorage> {
    client: Client,
    config: ContractConfig,
    storage: S,
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(rpc_url: &str, storage: S) -> Result<Self> {
        let config: ContractConfig = serde_json::from_str(DEPLOYMENT)?;
        let client = Client::new(rpc_url)?;

        // Retention-window check: if the RPC cannot serve events back to a
        // contract's deployment ledger, onboarding on a fresh DB will fail.
        for p in config.pools.iter().filter(|p| p.enabled) {
            match client
                .get_contract_events(&[p.pool_contract_id.to_string()], p.deployment_ledger, 1, None)
                .await
            {
                Ok(_) => {}
                Err(RpcError::RpcSyncGap(oldest)) => {
                    return Err(anyhow!(
                        "Your RPC node {rpc_url} oldest available ledger is {oldest}. \
Indexing requires events back to the pool deployment ledger {dep} for pool {pool}. \
Please use a fresher contracts deployment / a different RPC which stores events up to ledger {dep}.",
                        dep = p.deployment_ledger,
                        pool = p.pool_contract_id,
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        // ASP membership events are shared across pools. Use the earliest pool
        // deployment ledger as a cold-start anchor.
        if let Some(min_pool_ledger) = config
            .pools
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.deployment_ledger)
            .min()
        {
            match client
                .get_contract_events(&[config.asp_membership.to_string()], min_pool_ledger, 1, None)
                .await
            {
                Ok(_) => {}
                Err(RpcError::RpcSyncGap(oldest)) => {
                    return Err(anyhow!(
                        "Your RPC node {rpc_url} oldest available ledger is {oldest}. \
Indexing requires events back to ledger {dep} for ASP membership contract {asp}. \
Please use a fresher contracts deployment / a different RPC which stores events up to ledger {dep}.",
                        dep = min_pool_ledger,
                        asp = config.asp_membership,
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(Self {
            client,
            config,
            storage,
        })
    }

    pub async fn fetch_contract_events(&self) -> Result<()> {
        let network_tip = self.client.get_latest_ledger().await?.sequence;

        let enabled_pools: Vec<&types::PoolConfigEntry> =
            self.config.pools.iter().filter(|p| p.enabled).collect();
        if enabled_pools.is_empty() {
            return Ok(());
        }

        let min_pool_ledger = enabled_pools
            .iter()
            .map(|p| p.deployment_ledger)
            .min()
            .ok_or_else(|| anyhow!("no enabled pools in config"))?;

        let mut contract_ids: Vec<String> = enabled_pools
            .iter()
            .map(|p| p.pool_contract_id.clone())
            .collect();
        contract_ids.push(self.config.asp_membership.clone());
        contract_ids.push(self.config.asp_non_membership.clone());
        contract_ids.sort();
        contract_ids.dedup();

        let sync_scope_contract_id = &enabled_pools[0].pool_contract_id;
        let (mut cursor, start_ledger) = if let Some(SyncMetadata {
            cursor,
            last_ledger,
            ..
        }) = self.storage.get_sync_state(sync_scope_contract_id).await?
        {
            (Some(cursor), last_ledger)
        } else {
            (None, min_pool_ledger)
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );

            let (new_cursor, events, latest_ledger) = self
                .client
                .get_contract_events(&contract_ids, start_ledger, PAGE_SIZE, cursor)
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
                .save_sync_progress(sync_scope_contract_id, new_cursor.clone(), latest_ledger, is_empty)
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
    /// Gets the last synced ledger and cursor for the contract.
    async fn get_sync_state(&self, contract_id: &str) -> anyhow::Result<Option<SyncMetadata>>;

    /// Sends a batch of events to be saved and waits for confirmation.
    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()>;

    async fn save_sync_progress(
        &self,
        contract_id: &str,
        cursor: String,
        latest_ledger: u32,
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

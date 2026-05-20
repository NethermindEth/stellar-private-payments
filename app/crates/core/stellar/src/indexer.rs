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

        // 1) Pool contracts (one cursor per pool).
        for p in self.config.pools.iter().filter(|p| p.enabled) {
            self.fetch_one_contract(
                &p.pool_contract_id,
                p.deployment_ledger,
                network_tip,
            )
            .await?;
        }

        // 2) ASP membership contract (one cursor).
        if let Some(min_pool_ledger) = self
            .config
            .pools
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.deployment_ledger)
            .min()
        {
            self.fetch_one_contract(
                &self.config.asp_membership,
                min_pool_ledger,
                network_tip,
            )
            .await?;
        }

        Ok(())
    }

    async fn fetch_one_contract(
        &self,
        contract_id: &str,
        deployment_ledger: u32,
        network_tip: u32,
    ) -> Result<()> {
        log::debug!(
            "[INDEXER] starting round for contract={contract_id}, network_tip={network_tip}"
        );

        let (mut cursor, start_ledger) = if let Some(SyncMetadata {
            cursor,
            last_ledger,
            ..
        }) = self.storage.get_sync_state(contract_id).await?
        {
            (Some(cursor), last_ledger)
        } else {
            log::debug!(
                "[INDEXER] no saved sync metadata for contract {contract_id} - cold start at deployment ledger {deployment_ledger}"
            );
            (None, deployment_ledger)
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] contract={contract_id} page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );
            let (new_cursor, events, latest_ledger) = self
                .client
                .get_contract_events(&[contract_id.to_string()], start_ledger, PAGE_SIZE, cursor)
                .await?;

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let is_empty = events.is_empty();

            log::trace!(
                "[INDEXER] contract={contract_id} fetched {} events (latest_ledger={})",
                events.len(),
                latest_ledger
            );

            self.storage
                .save_events_batch(
                    contract_id,
                    ContractsEventData {
                        cursor: new_cursor.clone(),
                        latest_ledger,
                        events: events.into_iter().map(|e| e.into()).collect(),
                    },
                )
                .await?;

            cursor = Some(new_cursor);

            // Prove "caught up" by observing an empty page for the current cursor.
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
    async fn save_events_batch(
        &self,
        contract_id: &str,
        batch: ContractsEventData,
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

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

        // Retention-window check: if the RPC cannot serve events back to the deployment
        // ledger, onboarding on a fresh DB will fail to reconstruct Merkle
        // trees.
        let contract_ids = [config.pool.to_string(), config.asp_membership.to_string()];
        match client
            .get_contract_events(&contract_ids, config.deployment_ledger, 1, None)
            .await
        {
            Ok(_) => {}
            Err(RpcError::RpcSyncGap(oldest)) => {
                return Err(anyhow!(
                    "RPC_SYNC_GAP oldest={oldest} deployment={0} rpc={rpc_url}\n\
Your RPC node {rpc_url} oldest available ledger is {oldest}. \
Indexing requires events back to the pool deployment ledger {0}. \
Please use a fresher contracts deployment / a different RPC which stores events up to ledger {0}.",
                    config.deployment_ledger
                ));
            }
            Err(e) => return Err(e.into()),
        }

        Ok(Self {
            client,
            config,
            storage,
        })
    }

    pub async fn fetch_contract_events(&self) -> Result<()> {
        // Note - we don't index ASP nonmembership events here
        // self.config.asp_non_membership.to_string()
        // as SMT is stored onchain and we don't need events to rebuild it locally
        let contract_ids = [
            self.config.pool.to_string(),
            self.config.asp_membership.to_string(),
        ];
        let network_tip = self.client.get_latest_ledger().await?.sequence;
        log::debug!(
            "[INDEXER] starting new round for network tip {network_tip}, contract ids {contract_ids:?}"
        );
        let (mut cursor, start_ledger) = if let Some(SyncMetadata {
            cursor,
            last_ledger,
        }) = self.storage.get_sync_state().await?
        {
            (Some(cursor), last_ledger)
        } else {
            log::debug!(
                "[INDEXER] no saved sync metadata - cold start at deployment ledger {}",
                self.config.deployment_ledger
            );
            (None, self.config.deployment_ledger)
        };

        for page in 0..MAX_PAGES_PER_ROUND {
            log::trace!(
                "[INDEXER] page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );
            let (new_cursor, events, latest_ledger) = self
                .client
                .get_contract_events(&contract_ids, start_ledger, PAGE_SIZE, cursor)
                .await?;

            let new_cursor = new_cursor
                .clone()
                .ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let is_empty = events.is_empty();
            log::trace!(
                "[INDEXER] fetched {} events (latest_ledger={})",
                events.len(),
                latest_ledger
            );
            self.storage
                .save_events_batch(ContractsEventData {
                    cursor: new_cursor.clone(),
                    latest_ledger,
                    events: events.into_iter().map(|e| e.into()).collect(),
                })
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
    /// Gets the last synced ledger and cursor from the store
    async fn get_sync_state(&self) -> anyhow::Result<Option<SyncMetadata>>;

    /// Sends a batch of events to be saved and waits for confirmation
    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()>;
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

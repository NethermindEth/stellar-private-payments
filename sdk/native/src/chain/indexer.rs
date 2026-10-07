use crate::{
    chain::rpc::{Client, Error as RpcError},
    types::{ContractConfig, ContractsEventData, SyncMetadata},
};
use anyhow::{Result, anyhow};
use std::collections::HashSet;

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const PAGE_SIZE: usize = 1000;
const MAX_PAGES_PER_ROUND: usize = 10;

pub(crate) struct Indexer<S: ContractDataStorage> {
    client: Client,
    storage: S,
    config: ContractConfig,
    contract_ids: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IndexerError {
    #[error(transparent)]
    Rpc(#[from] RpcError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl<S: ContractDataStorage> Indexer<S> {
    pub async fn init(
        client: Client,
        storage: S,
        config: &ContractConfig,
    ) -> Result<Self, IndexerError> {
        let contract_ids = config.all_contract_ids();
        let (probe_ledger, _) = pass_start(config, &storage.get_sync_state().await?)?;

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
            config: config.clone(),
            contract_ids,
        })
    }

    /// Fetch up to [`MAX_PAGES_PER_ROUND`] event pages from RPC into storage.
    ///
    /// Returns `true` when another round may be needed. Returns `false` when
    /// caught up for now:
    /// - cursor did not advance, or
    /// - local sync ahead of the RPC events tip (`RpcAhead`).
    ///
    /// A full page (`PAGE_SIZE` events) always continues, even at the tip
    /// ledger, because more events may share that ledger.
    pub async fn fetch_contract_events(&self) -> Result<bool, IndexerError> {
        let network_tip = self.client.get_latest_ledger().await?.sequence;
        let (start_ledger, mut cursor) =
            pass_start(&self.config, &self.storage.get_sync_state().await?)?;
        let start_ledger = start_ledger.min(network_tip);

        let mut may_have_more = false;
        let mut progress_ledger = start_ledger;

        for page in 0..MAX_PAGES_PER_ROUND {
            tracing::trace!(
                "[INDEXER] bulk page {page}/{MAX_PAGES_PER_ROUND}, start_ledger={start_ledger}, network_tip={network_tip}, cursor={cursor:?}"
            );

            let prev_cursor = cursor.clone();
            let (new_cursor, events, latest_ledger) = match self
                .client
                .get_contract_events(&self.contract_ids, start_ledger, PAGE_SIZE, cursor)
                .await
            {
                Ok(page) => page,
                // We are ahead of the RPC's events tip: nothing to fetch until
                // it indexes further. Idle this round instead of erroring.
                Err(RpcError::RpcAhead(newest)) => {
                    tracing::debug!(
                        "[INDEXER] local sync (start_ledger={start_ledger}) is ahead of RPC events tip (newest={newest}); waiting for RPC to catch up"
                    );
                    tracing::info!("[INDEXER] synced to ledger {progress_ledger}");
                    return Ok(false);
                }
                Err(e) => return Err(e.into()),
            };

            let new_cursor =
                new_cursor.ok_or_else(|| anyhow!("cursor is not found in the events response"))?;
            let cursor_advanced = prev_cursor.as_deref() != Some(new_cursor.as_str());
            let at_events_tip = prev_cursor.is_some() && !cursor_advanced;
            if events.is_empty() {
                if at_events_tip {
                    progress_ledger = progress_ledger.max(latest_ledger);
                }
            } else {
                let page_ledger = events
                    .iter()
                    .map(|event| event.ledger)
                    .max()
                    .unwrap_or(latest_ledger);
                progress_ledger = progress_ledger.max(page_ledger);
            }

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
                    at_events_tip,
                )
                .await?;

            cursor = Some(new_cursor);
            if at_events_tip {
                tracing::info!("[INDEXER] synced to ledger {progress_ledger}");
                return Ok(false);
            }
            may_have_more = true;
        }

        Ok(may_have_more)
    }
}

/// Returns the ledger an indexing pass starts at, and the cursor it resumes
/// from.
///
/// Each contract resumes at its `last_indexed_ledger`; one without sync
/// metadata starts at its deployment ledger (the manifest's earliest for
/// `asp_membership` and the registry). The pass starts at the earliest of
/// these, and keeps the shared cursor only if every contract has metadata,
/// since that cursor is past a new contract's history.
fn pass_start(config: &ContractConfig, sync: &[SyncMetadata]) -> Result<(u32, Option<String>)> {
    let min_deployment_ledger = config.min_deployment_ledger()?;
    let resume_points: Vec<(u32, Option<&SyncMetadata>)> = config
        .indexed_contracts()
        .map(|(contract_id, deployment_ledger)| {
            let meta = sync.iter().find(|meta| meta.contract_id == contract_id);
            (
                meta.map_or(deployment_ledger.unwrap_or(min_deployment_ledger), |meta| {
                    meta.last_indexed_ledger
                }),
                meta,
            )
        })
        .collect();
    let start_ledger = resume_points
        .iter()
        .map(|(ledger, _)| *ledger)
        .min()
        .unwrap_or(min_deployment_ledger);
    let Some(active_sync) = resume_points
        .into_iter()
        .map(|(_, meta)| meta)
        .collect::<Option<Vec<_>>>()
    else {
        return Ok((start_ledger, None));
    };

    if active_sync
        .iter()
        .map(|meta| meta.last_indexed_ledger)
        .collect::<HashSet<_>>()
        .len()
        > 1
    {
        tracing::warn!(
            "[INDEXER] sync ledger divergence detected for {} active contracts; using min last_indexed_ledger={start_ledger}",
            active_sync.len()
        );
    }

    let unique_cursors: HashSet<&str> = active_sync
        .iter()
        .filter_map(|meta| (!meta.cursor.is_empty()).then_some(meta.cursor.as_str()))
        .collect();
    let cursor = if unique_cursors.len() <= 1 {
        active_sync
            .first()
            .and_then(|meta| (!meta.cursor.is_empty()).then(|| meta.cursor.clone()))
    } else {
        tracing::warn!(
            "[INDEXER] sync cursor divergence detected for {} active contracts; resetting cursor and replaying from ledger={start_ledger}",
            active_sync.len()
        );
        None
    };
    Ok((start_ledger, cursor))
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ContractDataStorage for crate::storage::StorageHandle {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        (**self).get_sync_state().await
    }

    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
        (**self).save_events_batch(batch).await
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        (**self).save_sync_progress(metadata, fully_indexed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Pools deployed at ledgers 200 and 100, and an ASP membership contract
    /// added at ledger 4,000.
    fn config() -> Result<ContractConfig> {
        let pool = |contract_id: &str, deployment_ledger: u32| {
            json!({
                "poolContractId": contract_id,
                "tokenContractId": "CTOKEN",
                "deploymentLedger": deployment_ledger,
                "enabled": true,
                "asset": {"kind": "native"},
                "policyFlags": ["allowlist"],
            })
        };
        Ok(serde_json::from_value(json!({
            "network": "test",
            "kdf_domain": "tests",
            "deployer": "GDEPLOYER",
            "admin": "GADMIN",
            "asp_membership": "CMEMBERSHIP",
            "added_asp_memberships": [{"contractId": "CADDED", "deploymentLedger": 4_000}],
            "asp_non_membership": "CNONMEMBERSHIP",
            "verifiers": {},
            "public_key_registry": "CREGISTRY",
            "pools": [pool("CPOOL_A", 200), pool("CPOOL_B", 100)],
        }))?)
    }

    fn progress(contract_id: &str, last_indexed_ledger: u32) -> SyncMetadata {
        SyncMetadata {
            contract_id: contract_id.to_string(),
            cursor: "CURSOR".to_string(),
            last_indexed_ledger,
            last_fully_indexed_ledger: 0,
        }
    }

    #[test]
    fn a_first_sync_starts_at_the_earliest_pool() -> Result<()> {
        assert_eq!(pass_start(&config()?, &[])?, (100, None));
        Ok(())
    }

    #[test]
    fn a_new_allowlist_replays_from_its_own_deployment() -> Result<()> {
        let config = config()?;
        let mut sync = ["CPOOL_A", "CPOOL_B", "CMEMBERSHIP", "CREGISTRY"]
            .map(|contract_id| progress(contract_id, 5_000));
        assert_eq!(pass_start(&config, &sync)?, (4_000, None));

        // A contract further behind than that deployment still sets the start.
        sync[0].last_indexed_ledger = 3_000;
        assert_eq!(pass_start(&config, &sync)?, (3_000, None));
        Ok(())
    }

    #[test]
    fn a_tree_without_progress_starts_at_the_manifest_minimum() -> Result<()> {
        let sync = ["CPOOL_A", "CPOOL_B", "CADDED", "CREGISTRY"]
            .map(|contract_id| progress(contract_id, 5_000));
        assert_eq!(pass_start(&config()?, &sync)?, (100, None));
        Ok(())
    }

    #[test]
    fn contracts_with_progress_resume_from_the_slowest() -> Result<()> {
        let mut sync = ["CPOOL_A", "CPOOL_B", "CMEMBERSHIP", "CADDED", "CREGISTRY"]
            .map(|contract_id| progress(contract_id, 5_000));
        sync[3].last_indexed_ledger = 4_500;
        assert_eq!(
            pass_start(&config()?, &sync)?,
            (4_500, Some("CURSOR".to_string()))
        );
        Ok(())
    }
}

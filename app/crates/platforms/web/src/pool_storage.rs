//! [`stellar_private_payments_sdk::pool_storage::PoolStorage`] backed by the
//! storage worker bridge.

use crate::{
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    workers::storage::StorageBridge,
};
use gloo_timers::future::TimeoutFuture;
use stellar_private_payments_sdk::{
    PoolError, PoolStorage, TransactRequest,
    chain::Client,
    state::StoredUserKeys,
    tx::flows::TransactParams,
    types::{ContractConfig, EncryptionPublicKey, NotePublicKey, SyncMetadata},
};
use tx_planner::SpendableNote;

/// Worker-backed pool storage for browser main-thread use.
#[derive(Clone)]
pub struct BridgePoolStorage {
    bridge: StorageBridge,
}

impl BridgePoolStorage {
    pub fn new(bridge: StorageBridge) -> Self {
        Self { bridge }
    }

    async fn call(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, PoolError> {
        self.bridge
            .call(req, timeout_ms)
            .await
            .map_err(|e| PoolError::Other(e.to_string()))
    }

    async fn sync_state(&self) -> Result<Vec<SyncMetadata>, PoolError> {
        match self.call(StorageWorkerRequest::SyncState, 5_000).await? {
            StorageWorkerResponse::SyncState(metadata) => Ok(metadata),
            other => Err(PoolError::Other(format!(
                "unexpected storage response loading sync state: {other:?}"
            ))),
        }
    }

    fn ledger_range(metadata: &[SyncMetadata]) -> (u32, u32) {
        let from = metadata
            .iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0);
        let to = metadata
            .iter()
            .map(|meta| meta.last_indexed_ledger)
            .max()
            .unwrap_or(from);
        (from, to)
    }
}

#[async_trait::async_trait(?Send)]
impl PoolStorage for BridgePoolStorage {
    async fn ensure_ready(&self) -> Result<(), PoolError> {
        self.bridge
            .ping()
            .await
            .map_err(|e| PoolError::Other(e.to_string()))
    }

    async fn spendable_wallet(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError> {
        match self
            .call(
                StorageWorkerRequest::UnspentUserNotes {
                    user_address: user_address.to_string(),
                    pool_contract_id: pool_contract_id.to_string(),
                },
                5_000,
            )
            .await?
        {
            StorageWorkerResponse::UserNotes(notes) => Ok(notes
                .into_iter()
                .map(|n| SpendableNote {
                    commitment: n.id,
                    amount: n.amount,
                })
                .collect()),
            other => Err(PoolError::Other(format!(
                "unexpected storage response loading wallet: {other:?}"
            ))),
        }
    }

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError> {
        match self
            .call(StorageWorkerRequest::Transact(req.clone()), 5_000)
            .await?
        {
            StorageWorkerResponse::TransactParams(params) => Ok(params),
            StorageWorkerResponse::AspMembershipSync(status) => {
                Err(PoolError::MembershipSync(status))
            }
            other => Err(PoolError::Other(format!(
                "unexpected storage response building transact params: {other:?}"
            ))),
        }
    }

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError> {
        let _ = user_address;
        Err(PoolError::Other(
            "full user keys are not available on the storage bridge; use user_public_keys".into(),
        ))
    }

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        match self
            .call(
                StorageWorkerRequest::UserKeys(user_address.to_string()),
                1_000,
            )
            .await?
        {
            StorageWorkerResponse::UserKeys(keys) => {
                let keys = keys.ok_or_else(|| {
                    PoolError::Other("user keys not found in worker storage".into())
                })?;
                Ok((keys.note_keypair.public, keys.encryption_keypair.public))
            }
            other => Err(PoolError::Other(format!(
                "unexpected storage response loading user keys: {other:?}"
            ))),
        }
    }

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, PoolError> {
        Ok(self.user_public_keys(user_address).await?.0)
    }

    async fn sync_indexer(
        &self,
        rpc_url: &str,
        _contract_config: &ContractConfig,
    ) -> Result<(u32, u32), PoolError> {
        let rpc =
            Client::new(rpc_url).map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;
        let from = Self::ledger_range(&self.sync_state().await?).0;

        loop {
            let tip = rpc
                .get_latest_ledger()
                .await
                .map_err(|e| PoolError::Other(format!("latest ledger: {e:#}")))?
                .sequence;
            let metadata = self.sync_state().await?;
            let (_, to) = Self::ledger_range(&metadata);
            if to >= tip {
                return Ok((from, to));
            }
            TimeoutFuture::new(1_000).await;
        }
    }
}

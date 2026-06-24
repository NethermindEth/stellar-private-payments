//! [`stellar_private_payments_sdk::pool_storage::PoolStorage`] backed by the
//! storage worker bridge.

use crate::{
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    workers::storage::StorageBridge,
};
use stellar_private_payments_sdk::{
    PoolError, PoolStorage, TransactRequest,
    state::StoredUserKeys,
    tx::flows::TransactParams,
    types::{EncryptionPublicKey, NotePublicKey},
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
}

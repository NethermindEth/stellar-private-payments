//! Pluggable async wallet storage for [`crate::pool::PrivatePool`].

use prover::flows::TransactParams;
use state::{Storage as SqliteStorage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{ContractConfig, EncryptionPublicKey, NotePublicKey};

use crate::{
    error::PoolError,
    transact::{BuildTransactParams, TransactRequest},
};

#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub use native::LocalStorage;

pub(crate) fn map_build_params(
    result: anyhow::Result<BuildTransactParams>,
) -> Result<TransactParams, PoolError> {
    match result.map_err(|e| PoolError::Other(e.to_string()))? {
        BuildTransactParams::Ready(params) => Ok(params),
        BuildTransactParams::MembershipSync(status) => Err(PoolError::MembershipSync(status)),
    }
}

pub(crate) fn map_user_keys(
    storage: &SqliteStorage,
    user_address: &str,
) -> Result<StoredUserKeys, PoolError> {
    storage
        .get_user_keys(user_address)
        .map_err(|e| PoolError::Other(e.to_string()))?
        .ok_or_else(|| {
            PoolError::Other(format!(
                "address {user_address} should generate privacy keys and ASP secret first"
            ))
        })
}

pub(crate) fn spendable_wallet_from_storage(
    storage: &SqliteStorage,
    pool_contract_id: &str,
    user_address: &str,
) -> Result<Vec<SpendableNote>, PoolError> {
    storage
        .list_unspent_user_notes(pool_contract_id, user_address)
        .map_err(|e| PoolError::Other(e.to_string()))
        .map(|notes| {
            notes
                .into_iter()
                .map(|n| SpendableNote {
                    commitment: n.id,
                    amount: n.amount,
                })
                .collect()
        })
}

/// Wallet + transact-param reads for [`crate::pool::PrivatePool`].
#[async_trait::async_trait(?Send)]
pub trait Storage {
    async fn ensure_ready(&self) -> Result<(), PoolError>;

    async fn spendable_wallet(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, PoolError>;

    async fn build_transact_params(
        &self,
        req: &TransactRequest,
    ) -> Result<TransactParams, PoolError>;

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, PoolError>;

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError>;

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, PoolError> {
        Ok(self.user_public_keys(user_address).await?.0)
    }

    /// Fetch indexer events and process local state. Returns ledger range
    /// synced.
    async fn sync_indexer(
        &self,
        _rpc_url: &str,
        _contract_config: &ContractConfig,
    ) -> Result<(u32, u32), PoolError> {
        Err(PoolError::Other(
            "sync not supported for this storage backend".into(),
        ))
    }
}

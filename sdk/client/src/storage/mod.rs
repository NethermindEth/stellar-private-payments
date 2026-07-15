//! Pluggable async wallet storage for [`crate::pool::PrivatePool`].

use prover::flows::TransactParams;
use state::{SqliteStorage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{
    ContractConfig, EncryptionPublicKey, NotePublicKey, PortfolioBalance, UserNoteSummary,
};

use crate::{
    disclosure::{DisclosureInputs, DisclosureInputsRequest},
    error::Error,
    transact::{BuildTransactParams, TransactRequest},
};

mod local;

pub use local::LocalStorage;

pub(crate) fn map_build_params(
    result: anyhow::Result<BuildTransactParams>,
) -> Result<TransactParams, Error> {
    match result.map_err(|e| Error::Other(e.to_string()))? {
        BuildTransactParams::Ready(params) => Ok(*params),
        BuildTransactParams::MembershipSync(status) => Err(Error::MembershipSync(status)),
    }
}

pub(crate) fn map_user_keys(
    storage: &SqliteStorage,
    user_address: &str,
) -> Result<StoredUserKeys, Error> {
    storage
        .get_user_keys(user_address)
        .map_err(|e| Error::Other(e.to_string()))?
        .ok_or_else(|| {
            Error::Other(format!(
                "address {user_address} should generate privacy keys and ASP secret first"
            ))
        })
}

pub(crate) fn spendable_notes_from_storage(
    storage: &SqliteStorage,
    pool_contract_id: &str,
    user_address: &str,
) -> Result<Vec<SpendableNote>, Error> {
    storage
        .list_unspent_user_notes(pool_contract_id, user_address)
        .map_err(|e| Error::Other(e.to_string()))
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

pub(crate) fn pool_notes_from_storage(
    storage: &SqliteStorage,
    pool_contract_id: &str,
    user_address: &str,
) -> Result<Vec<UserNoteSummary>, Error> {
    storage
        .list_pool_user_notes(pool_contract_id, user_address)
        .map_err(|e| Error::Other(e.to_string()))
}

pub(crate) fn portfolio_balances_from_storage(
    storage: &SqliteStorage,
    user_address: &str,
    config: &ContractConfig,
) -> Result<Vec<PortfolioBalance>, Error> {
    storage
        .list_portfolio_balances(user_address, config)
        .map_err(|e| Error::Other(e.to_string()))
}

/// Wallet reads and sync lifecycle for [`crate::pool::PrivatePool`].
#[async_trait::async_trait(?Send)]
pub trait Storage: stellar::ContractDataStorage {
    /// Independent handle for a concurrent consumer
    fn fork(&self) -> Result<Self, Error>
    where
        Self: Sized;

    async fn ensure_ready(&self) -> Result<(), Error>;

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<SpendableNote>, Error>;

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
    ) -> Result<Vec<UserNoteSummary>, Error>;

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        config: &ContractConfig,
    ) -> Result<Vec<PortfolioBalance>, Error>;

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error>;

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error>;

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, Error>;

    async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error>;

    async fn user_note_pubkey(&self, user_address: &str) -> Result<NotePublicKey, Error> {
        Ok(self.user_public_keys(user_address).await?.0)
    }

    async fn registered_public_keys(
        &self,
        address: &str,
        public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error>;

    /// Finalize local processing after RPC ingest
    async fn process_pending_state(&self) -> Result<(), Error>;
}

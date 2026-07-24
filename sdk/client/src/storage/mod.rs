//! Pluggable async wallet storage for [`crate::pool::PrivatePool`].

use prover::flows::TransactParams;
use state::{SqliteStorage, StoredUserKeys};
use tx_planner::SpendableNote;
use types::{
    ContractConfig, EncryptionPublicKey, Field, NotePublicKey, OperationalFeedItem,
    PortfolioBalance, RecipientLookup, UserNoteSummary, UserNotesPage,
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

pub(crate) fn user_notes_page_from_storage(
    storage: &SqliteStorage,
    user_address: &str,
    offset: u32,
    limit: u32,
    spent: Option<bool>,
) -> Result<UserNotesPage, Error> {
    storage
        .list_user_notes_page(user_address, offset, limit, spent)
        .map_err(|e| Error::Other(e.to_string()))
}

pub(crate) fn operational_feed_from_storage(
    storage: &SqliteStorage,
    limit: u32,
    config: &ContractConfig,
) -> Result<Vec<OperationalFeedItem>, Error> {
    storage
        .get_operational_feed(limit, &config.asp_membership, &config.public_key_registry)
        .map_err(|e| Error::Other(e.to_string()))
}

pub(crate) fn recipient_lookup_from_storage(
    storage: &SqliteStorage,
    address: &str,
    config: &ContractConfig,
) -> Result<RecipientLookup, Error> {
    storage
        .recipient_lookup(address, &config.public_key_registry)
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

    async fn list_user_notes_page(
        &self,
        user_address: &str,
        offset: u32,
        limit: u32,
        spent: Option<bool>,
    ) -> Result<UserNotesPage, Error>;

    async fn operational_feed(
        &self,
        limit: u32,
        config: &ContractConfig,
    ) -> Result<Vec<OperationalFeedItem>, Error>;

    async fn recipient_lookup(
        &self,
        address: &str,
        config: &ContractConfig,
    ) -> Result<RecipientLookup, Error>;

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error>;

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error>;

    async fn user_keys(&self, user_address: &str) -> Result<StoredUserKeys, Error>;

    async fn asp_secret(&self, user_address: &str) -> Result<Field, Error>;

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

    /// Clear RPC pagination cursors so the indexer resumes by ledger (used on
    /// wallet↔bootnode handoff).
    async fn clear_indexing_cursors(&self) -> Result<(), Error>;
}

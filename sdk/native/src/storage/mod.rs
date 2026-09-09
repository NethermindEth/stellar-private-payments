//! Pluggable async wallet storage for [`crate::pool::PrivatePool`].

use crate::{
    gvk::GvkEvent,
    planner::SpendableNote,
    state::{KeyLookup, SqliteStorage, StoredUserKeys},
    types::{
        ContractConfig, EncryptionPublicKey, Field, NotePublicKey, OperationalFeedItem,
        PortfolioBalance, PortfolioPoolEntry, RecipientLookup, UserNoteSummary,
    },
    zk::flows::TransactParams,
};

use crate::{
    disclosure::{DisclosureInputs, DisclosureInputsRequest},
    error::Error,
    transact::{BuildTransactParams, TransactRequest},
};

mod local;

use std::collections::HashSet;

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
    match storage
        .get_user_keys_bound(
            user_address,
            storage
                .require_binding()
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?
    {
        KeyLookup::Found(keys) => Ok(keys),
        // Escapes to CLI output and logs.
        KeyLookup::Absent => Err(Error::Other(format!(
            "address {} should generate privacy keys and ASP secret first",
            crate::types::Sensitive(user_address)
        ))),
        // Distinct from Absent on purpose: telling a user to generate keys
        // they already have, and whose generation would be refused, sends
        // them somewhere that cannot work.
        KeyLookup::Mismatch(_) => Err(Error::Other(format!(
            "the privacy keys stored for address {} were derived for a different deployment \
             configuration and cannot be used here",
            crate::types::Sensitive(user_address)
        ))),
    }
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
    enabled_pools: &[PortfolioPoolEntry],
) -> Result<Vec<PortfolioBalance>, Error> {
    storage
        .list_portfolio_balances(user_address, enabled_pools)
        .map_err(|e| Error::Other(e.to_string()))
}

pub(crate) fn user_notes_from_storage(
    storage: &SqliteStorage,
    user_address: &str,
    limit: u32,
) -> Result<Vec<UserNoteSummary>, Error> {
    storage
        .list_user_notes(user_address, limit)
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
pub trait Storage: crate::chain::ContractDataStorage {
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
        enabled_pools: &[PortfolioPoolEntry],
    ) -> Result<Vec<PortfolioBalance>, Error>;

    async fn list_user_notes(
        &self,
        user_address: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error>;

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

    /// Bind this handle to the deployment's required key binding.
    ///
    /// Every reader that returns key material consults it, and an
    /// unconfigured handle refuses rather than guessing, so a client must
    /// call this before any session reads keys. Implementors that fork or
    /// reopen a connection must carry it onto the new handle.
    fn set_required_binding(&mut self, required: crate::state::BindingVersion);

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

    /// Lower proven catch-up ledger after bootnode handoff (retention cutoff).
    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error>;

    /// Pool-gvk events in `(ledger, event_id)` order.
    async fn list_pool_gvk_events(
        &self,
        pool_contract_id: &str,
        after: Option<(u32, String)>,
        limit: u32,
    ) -> Result<Vec<GvkEvent>, Error>;

    /// Subset of `commitments` registered for `pool_contract_id`.
    async fn pool_has_commitments(
        &self,
        pool_contract_id: &str,
        commitments: &[Field],
    ) -> Result<HashSet<Field>, Error>;
}

#[cfg(test)]
mod tests {
    use super::map_user_keys;
    use crate::{
        state::SqliteStorage,
        types::{lock_reveal_flag, set_reveal_sensitive},
    };

    const ADDRESS: &str = "GTESTACCOUNTWITHNOSTOREDKEYS";

    #[test]
    fn missing_user_keys_error_redacts_the_address() {
        let _guard = lock_reveal_flag();
        set_reveal_sensitive(false);
        let mut storage = SqliteStorage::connect_in_memory().expect("in-memory storage");
        // v1 is the split-free binding these fixtures represent; an
        // unconfigured handle now refuses to read key material at all.
        storage.set_required_binding(crate::state::BindingVersion::V1);

        let err = map_user_keys(&storage, ADDRESS).expect_err("no keys are stored");
        let rendered = err.to_string();

        assert!(!rendered.contains(ADDRESS), "address leaked: {rendered}");
        assert!(rendered.contains("<redacted>"), "not redacted: {rendered}");
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod binding_enforcement_tests {
    use super::*;
    use crate::{
        state::{BindingVersion, KeyBinding},
        types::{
            EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey, Field, NoteKeyPair,
            NotePrivateKey, NotePublicKey,
        },
    };

    const ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn keys() -> (NoteKeyPair, EncryptionKeyPair, Field) {
        (
            NoteKeyPair {
                private: NotePrivateKey([7u8; 32]),
                public: NotePublicKey([8u8; 32]),
            },
            EncryptionKeyPair {
                private: EncryptionPrivateKey([9u8; 32]),
                public: EncryptionPublicKey([10u8; 32]),
            },
            Field::try_from_le_bytes([0u8; 32]).expect("field"),
        )
    }

    /// A v2 row must not be readable on a deployment that requires v1, and a
    /// mismatch must be distinguishable from an absent row: telling a user to
    /// generate keys they already hold sends them somewhere that cannot work.
    #[test]
    fn reader_refuses_foreign_binding_with_a_distinct_error() {
        let mut storage = SqliteStorage::connect_in_memory().expect("open storage");
        let (note, enc, blinding) = keys();
        storage
            .save_encryption_and_note_keypairs_bound(
                ADDRESS,
                &note,
                &enc,
                &blinding,
                &KeyBinding {
                    version: BindingVersion::V2,
                    bound_owner: Some(ADDRESS.to_string()),
                },
            )
            .expect("save v2 row");

        storage.set_required_binding(BindingVersion::V2);
        map_user_keys(&storage, ADDRESS).expect("v2 row readable when v2 is required");

        storage.set_required_binding(BindingVersion::V1);
        let err = map_user_keys(&storage, ADDRESS)
            .expect_err("v2 row must not be readable when v1 is required")
            .to_string();
        assert!(
            err.contains("different deployment configuration"),
            "mismatch must be distinct from absent, got: {err}"
        );
        assert!(
            !err.contains("should generate privacy keys"),
            "mismatch must not tell the user to generate keys they already have: {err}"
        );
        for forbidden in ["rejected", "denied", "cancelled"] {
            assert!(
                !err.to_lowercase().contains(forbidden),
                "error wording must stay clear of the cancellation classifier: {err}"
            );
        }
        assert!(
            !err.contains(ADDRESS),
            "the address must be redacted in the rendered error: {err}"
        );
    }

    /// An unconfigured handle must refuse to return key material rather than
    /// fall back to a binding. Falling back to v1 would *accept* a v1 row on a
    /// deployment that requires v2 - the exact case the binding exists to
    /// refuse - so "unset" and "v1" cannot be the same state.
    #[test]
    fn unconfigured_handle_refuses_key_material() {
        let mut storage = SqliteStorage::connect_in_memory().expect("open storage");
        let (note, enc, blinding) = keys();
        storage
            .save_encryption_and_note_keypairs(ADDRESS, &note, &enc, &blinding)
            .expect("save v1 row");

        let err = map_user_keys(&storage, ADDRESS)
            .expect_err("an unconfigured handle must not return key material")
            .to_string();
        assert!(
            err.contains("has not been configured"),
            "expected a configuration error, got: {err}"
        );

        storage.set_required_binding(BindingVersion::V1);
        map_user_keys(&storage, ADDRESS).expect("readable once the requirement is configured");
    }

    /// Every account session is a fork of the client's handle, and a fork
    /// opens a fresh connection rather than cloning one, so a requirement that
    /// did not survive forking would leave every session unconfigured - or,
    /// worse under a v1 default, accepting rows a v2 deployment must refuse.
    #[test]
    fn fork_preserves_the_required_binding() {
        use crate::storage::{Storage as StorageTrait, local::LocalStorage};

        let path = std::env::temp_dir().join(format!(
            "spp-binding-fork-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        {
            let mut db = SqliteStorage::connect_file(&path).expect("open db");
            let (note, enc, blinding) = keys();
            db.save_encryption_and_note_keypairs_bound(
                ADDRESS,
                &note,
                &enc,
                &blinding,
                &KeyBinding {
                    version: BindingVersion::V2,
                    bound_owner: Some(ADDRESS.to_string()),
                },
            )
            .expect("save v2 row");
        }

        let local = LocalStorage::open(path.to_str().expect("utf-8 path"))
            .expect("open local storage")
            .with_required_binding(BindingVersion::V2);
        let forked = StorageTrait::fork(&local).expect("fork");
        map_user_keys(&forked.storage(), ADDRESS)
            .expect("a forked handle must keep the deployment's requirement");

        let unset = LocalStorage::open(path.to_str().expect("utf-8 path")).expect("open again");
        map_user_keys(&unset.storage(), ADDRESS)
            .expect_err("an unconfigured handle must refuse even a well-formed row");

        let _ = std::fs::remove_file(&path);
    }

    /// Background scanning attributes notes by trying every account's keys, so
    /// a row this deployment does not require must be omitted from that set
    /// rather than trial-decrypted.
    #[test]
    fn scan_skips_foreign_binding_rows() {
        let mut storage = SqliteStorage::connect_in_memory().expect("open storage");
        let (note, enc, blinding) = keys();
        storage
            .save_encryption_and_note_keypairs_bound(
                ADDRESS,
                &note,
                &enc,
                &blinding,
                &KeyBinding {
                    version: BindingVersion::V2,
                    bound_owner: Some(ADDRESS.to_string()),
                },
            )
            .expect("save v2 row");

        assert_eq!(
            storage
                .get_accounts_with_latest_keypairs_bound(BindingVersion::V2)
                .expect("bound scan")
                .len(),
            1,
            "the row is visible to a deployment that requires v2"
        );
        assert!(
            storage
                .get_accounts_with_latest_keypairs_bound(BindingVersion::V1)
                .expect("bound scan")
                .is_empty(),
            "a v2 row must be omitted from the scan set when v1 is required"
        );
    }
}

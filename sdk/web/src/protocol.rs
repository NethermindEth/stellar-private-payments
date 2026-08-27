use serde::{Deserialize, Serialize};

/// Wrapper that carries a correlation/operation ID across the gloo-worker
/// boundary. The worker re-attaches `correlation_id` as a tracing span field.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelatedRequest<T> {
    pub correlation_id: String,
    pub payload: T,
}

pub use stellar_private_payments::{
    DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams, PreparedProverTx,
    TransactRequest,
};

use stellar_private_payments::{
    types::{
        AspMembershipSync, ContractsEventData, DisclosureReceipt, EncryptionPublicKey, Field,
        KeyDerivationSignature, NotePublicKey, OperationalFeedItem, PortfolioBalance,
        RecipientLookup, SyncMetadata, UserNoteSummary, UserOperation,
    },
    zk::flows::TransactParams,
};

pub type Address = String;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicNoteKeyPair {
    pub public: NotePublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicEncryptionKeyPair {
    pub public: EncryptionPublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeys {
    pub note_keypair: PublicNoteKeyPair,
    pub encryption_keypair: PublicEncryptionKeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspSecret {
    pub membership_blinding: Field,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclaimerStatePayload {
    pub disclaimer_text_md: String,
    pub disclaimer_hash_hex: String,
    pub accepted: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerRequest {
    Ping,
    SyncState,
    ProcessPendingState,
    SaveEvents(ContractsEventData),
    SaveSyncProgress {
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    },
    ClearIndexingCursors,
    ClampLastFullyIndexedLedger(u32),
    DeriveSaveUserKeys(Address, KeyDerivationSignature, String),
    DisclaimerState(Address),
    AcceptDisclaimer(Address, String),
    GetSetting(String),
    SetSetting {
        key: String,
        value_json: String,
    },
    UserKeys(Address),
    AspSecret(Address),
    UserNotes(Address, u32),
    PortfolioBalances(Address),
    RecordOperation {
        address: Address,
        pool_contract_id: String,
        op_type: String,
        amount: String,
        direction: String,
        counterparty: Option<String>,
        tx_hash: Option<String>,
    },
    ListOperations {
        address: Address,
        pool_contract_id: String,
        limit: u32,
    },
    UnspentUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    PoolUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    RecipientLookup {
        address: Address,
        public_key_registry_contract_id: String,
    },
    OperationalFeed {
        limit: u32,
        asp_membership_contract_id: String,
        public_key_registry_contract_id: String,
    },
    DisclosureInputs(DisclosureInputsRequest),
    Transact(TransactRequest),
    DeriveASPleaf(AdminASPRequest),
    ConfigureTelemetry(WorkerTelemetryConfig),
    DumpLogs,
    /// Bind the worker to the account whose wallet session the client has
    /// opened. Not reachable from [`crate::storage::Storage::call`].
    BindSession(Address),
    /// Drop the binding, revoking the capability without touching the data.
    UnbindSession,
}

impl StorageWorkerRequest {
    /// Whether this request may only be served for the account the worker is
    /// bound to.
    ///
    /// The line is *key material*: `AspSecret`, `DeriveSaveUserKeys`,
    /// `DisclosureInputs` and `Transact` all read or write private keys, and
    /// `BindSession`/`UnbindSession` decide which account those four serve.
    /// For all of them the address must come from an established wallet
    /// session, never from the caller.
    ///
    /// `UserKeys` is not privileged: it returns public keys only and has to run
    /// during onboarding, before any session exists. The note and balance
    /// queries are also unprivileged — a caller can still name any address to
    /// read them, which is a real weakness but needs a general read policy
    /// rather than this guard.
    pub(crate) fn requires_bound_session(&self) -> bool {
        matches!(
            self,
            Self::AspSecret(_)
                | Self::DeriveSaveUserKeys(..)
                | Self::DisclosureInputs(_)
                | Self::Transact(_)
                | Self::BindSession(_)
                | Self::UnbindSession
        )
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod privileged_request_tests {
    use super::*;
    use stellar_private_payments::types::KeyDerivationSignature;

    const ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    #[test]
    fn key_material_requests_are_privileged() {
        assert!(StorageWorkerRequest::AspSecret(ADDR.to_string()).requires_bound_session());
        assert!(
            StorageWorkerRequest::DeriveSaveUserKeys(
                ADDR.to_string(),
                KeyDerivationSignature(vec![0u8; 64]),
                "Test Network".to_string(),
            )
            .requires_bound_session()
        );
        assert!(StorageWorkerRequest::BindSession(ADDR.to_string()).requires_bound_session());
        assert!(StorageWorkerRequest::UnbindSession.requires_bound_session());
    }

    #[test]
    fn zk_input_builders_are_privileged_too() {
        // These return note_private_key / note_blinding for the account their
        // request names, so they leak strictly more than AspSecret does.
        assert!(
            StorageWorkerRequest::DisclosureInputs(DisclosureInputsRequest {
                user_address: ADDR.to_string(),
                pool_address: "CPOOL".to_string(),
                selected_commitments: Vec::new(),
                pool_root: None,
                pool_next_index: 0,
                tree_depth: 20,
            })
            .requires_bound_session()
        );
    }

    #[test]
    fn the_public_key_probe_stays_reachable() {
        // Onboarding calls this before any session exists; privileging it
        // would deadlock the flow it is part of.
        assert!(!StorageWorkerRequest::UserKeys(ADDR.to_string()).requires_bound_session());
    }

    #[test]
    fn app_persistence_requests_stay_reachable() {
        // The app's own AppStorage layer reaches the worker through
        // Storage.call for all of these; none touch key material.
        assert!(!StorageWorkerRequest::GetSetting("explorer".into()).requires_bound_session());
        assert!(
            !StorageWorkerRequest::SetSetting {
                key: "explorer".into(),
                value_json: "{}".into(),
            }
            .requires_bound_session()
        );
        assert!(!StorageWorkerRequest::DisclaimerState(ADDR.to_string()).requires_bound_session());
        assert!(
            !StorageWorkerRequest::AcceptDisclaimer(ADDR.to_string(), "abc".into())
                .requires_bound_session()
        );
        assert!(!StorageWorkerRequest::Ping.requires_bound_session());
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerResponse {
    Pong,
    SyncState(Vec<SyncMetadata>),
    Saved,
    Error(String),
    DisclaimerState(DisclaimerStatePayload),
    Setting(Option<String>),
    UserKeys(Option<UserKeys>),
    AspSecret(Option<AspSecret>),
    UserNotes(Vec<UserNoteSummary>),
    PortfolioBalances(Vec<PortfolioBalance>),
    Operations(Vec<UserOperation>),
    RecipientLookup(RecipientLookup),
    OperationalFeed(Vec<OperationalFeedItem>),
    AspMembershipSync(AspMembershipSync),
    DisclosureNotes(Vec<DisclosureInputs>),
    TransactParams(TransactParams),
    DeriveASPleaf(Field),
    Logs(String),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerRequest {
    Ping,
    Transact(TransactParams),
    Disclosure(DisclosureProveParams),
    VerifyDisclosureProof(DisclosureReceipt, String),
    ConfigureTelemetry(WorkerTelemetryConfig),
    DumpLogs,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerResponse {
    Pong,
    Error(String),
    TransactPrepared(PreparedProverTx),
    Disclosure(DisclosureReceipt),
    DisclosureProofVerified(bool),
    Logs(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminASPRequest {
    pub membership_blinding: Field,
    pub pubkey: NotePublicKey,
}

/// Telemetry configuration pushed from the main thread to worker isolates.
/// Only the knobs that make sense per-isolate: sink targets and ring-buffer
/// sizing stay per-isolate defaults and are not broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerTelemetryConfig {
    pub level: String,
    pub reveal_sensitive: bool,
}

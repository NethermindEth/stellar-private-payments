use serde::{Deserialize, Serialize};

/// Wrapper that carries a correlation/operation ID across the gloo-worker
/// boundary. The worker re-attaches `correlation_id` as a tracing span field.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelatedRequest<T> {
    pub correlation_id: String,
    pub payload: T,
}

pub use stellar_private_payments::{
    disclosure::{DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams},
    transact::{PreparedProverTx, TransactRequest},
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
    /// Support diagnostic for the ambiguous-keypairs recovery case. Bypasses
    /// the worker's normal `STORAGE` slot, since it must work when that slot
    /// is empty because `Storage::connect()` itself failed.
    DiagnoseAmbiguousKeypairs {
        account_address: Address,
    },
}

/// How a request interacts with the worker's session binding. Assigned by
/// [`StorageWorkerRequest::session_policy`] and enforced centrally by the
/// worker router and the raw `Storage.call` surface.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionPolicy<'a> {
    /// Establishes or revokes the binding itself.
    SessionControl,
    /// Private key material for the named account.
    KeyMaterial(&'a Address),
    /// A write served only under a bound session.
    BoundWrite { address: Option<&'a Address> },
    /// An account-data read served only for the bound account.
    BoundRead(&'a Address),
    /// A documented public exception, reachable before any session exists.
    Public,
}

impl StorageWorkerRequest {
    /// The access policy for this request. Exhaustive match, no wildcard, so
    /// a new variant must be classified to compile.
    pub(crate) fn session_policy(&self) -> SessionPolicy<'_> {
        match self {
            Self::BindSession(_) | Self::UnbindSession => SessionPolicy::SessionControl,
            Self::AspSecret(address) | Self::DeriveSaveUserKeys(address, ..) => {
                SessionPolicy::KeyMaterial(address)
            }
            Self::DisclosureInputs(req) => SessionPolicy::KeyMaterial(&req.user_address),
            Self::Transact(req) => SessionPolicy::KeyMaterial(&req.user_address),
            Self::AcceptDisclaimer(address, _) | Self::RecordOperation { address, .. } => {
                SessionPolicy::BoundWrite {
                    address: Some(address),
                }
            }
            Self::SaveEvents(_)
            | Self::SaveSyncProgress { .. }
            | Self::ClearIndexingCursors
            | Self::ClampLastFullyIndexedLedger(_)
            | Self::ProcessPendingState => SessionPolicy::BoundWrite { address: None },
            Self::UserNotes(address, _)
            | Self::PortfolioBalances(address)
            | Self::ListOperations { address, .. } => SessionPolicy::BoundRead(address),
            Self::UnspentUserNotes { user_address, .. }
            | Self::PoolUserNotes { user_address, .. } => SessionPolicy::BoundRead(user_address),
            Self::Ping
            | Self::SyncState
            | Self::GetSetting(_)
            | Self::SetSetting { .. }
            | Self::UserKeys(_)
            | Self::DisclaimerState(_)
            | Self::RecipientLookup { .. }
            | Self::OperationalFeed { .. }
            | Self::DeriveASPleaf(_)
            | Self::ConfigureTelemetry(_)
            | Self::DumpLogs
            | Self::DiagnoseAmbiguousKeypairs { .. } => SessionPolicy::Public,
        }
    }

    /// Whether the raw `Storage.call` surface refuses this request outright.
    pub(crate) fn requires_bound_session(&self) -> bool {
        matches!(
            self.session_policy(),
            SessionPolicy::SessionControl | SessionPolicy::KeyMaterial(_)
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

    #[test]
    fn session_control_is_classified_separately_from_key_material() {
        assert_eq!(
            StorageWorkerRequest::BindSession(ADDR.to_string()).session_policy(),
            SessionPolicy::SessionControl
        );
        assert_eq!(
            StorageWorkerRequest::UnbindSession.session_policy(),
            SessionPolicy::SessionControl
        );
        assert_eq!(
            StorageWorkerRequest::AspSecret(ADDR.to_string()).session_policy(),
            SessionPolicy::KeyMaterial(&ADDR.to_string())
        );
    }

    #[test]
    fn account_record_writes_are_bound_to_the_named_account() {
        for request in [
            StorageWorkerRequest::AcceptDisclaimer(ADDR.to_string(), "abc".into()),
            StorageWorkerRequest::RecordOperation {
                address: ADDR.to_string(),
                pool_contract_id: "CPOOL".into(),
                op_type: "deposit".into(),
                amount: "1".into(),
                direction: "in".into(),
                counterparty: None,
                tx_hash: None,
            },
        ] {
            assert_eq!(
                request.session_policy(),
                SessionPolicy::BoundWrite {
                    address: Some(&ADDR.to_string())
                },
                "account-record write must be bound to its address: {request:?}"
            );
        }
    }

    #[test]
    fn chain_state_writes_require_a_session_without_an_address() {
        for request in [
            StorageWorkerRequest::SaveEvents(ContractsEventData {
                events: Vec::new(),
                cursor: String::new(),
                latest_ledger: 0,
            }),
            StorageWorkerRequest::SaveSyncProgress {
                metadata: Vec::new(),
                fully_indexed: false,
            },
            StorageWorkerRequest::ClearIndexingCursors,
            StorageWorkerRequest::ClampLastFullyIndexedLedger(0),
            StorageWorkerRequest::ProcessPendingState,
        ] {
            assert_eq!(
                request.session_policy(),
                SessionPolicy::BoundWrite { address: None },
                "chain-state write must require a bound session: {request:?}"
            );
        }
    }

    #[test]
    fn account_data_reads_are_bound_to_the_named_account() {
        for request in [
            StorageWorkerRequest::UserNotes(ADDR.to_string(), 10),
            StorageWorkerRequest::PortfolioBalances(ADDR.to_string()),
            StorageWorkerRequest::ListOperations {
                address: ADDR.to_string(),
                pool_contract_id: "CPOOL".into(),
                limit: 10,
            },
            StorageWorkerRequest::UnspentUserNotes {
                user_address: ADDR.to_string(),
                pool_contract_id: "CPOOL".into(),
            },
            StorageWorkerRequest::PoolUserNotes {
                user_address: ADDR.to_string(),
                pool_contract_id: "CPOOL".into(),
            },
        ] {
            let expected_address = match &request {
                StorageWorkerRequest::UnspentUserNotes { user_address, .. }
                | StorageWorkerRequest::PoolUserNotes { user_address, .. } => user_address,
                _ => &ADDR.to_string(),
            };
            assert_eq!(
                request.session_policy(),
                SessionPolicy::BoundRead(expected_address),
                "account-data read must be bound to its account: {request:?}"
            );
        }
    }

    #[test]
    fn every_public_exception_is_named_explicitly() {
        let exceptions = [
            StorageWorkerRequest::Ping,
            StorageWorkerRequest::SyncState,
            StorageWorkerRequest::GetSetting("explorer".into()),
            StorageWorkerRequest::SetSetting {
                key: "explorer".into(),
                value_json: "{}".into(),
            },
            StorageWorkerRequest::UserKeys(ADDR.to_string()),
            StorageWorkerRequest::DisclaimerState(ADDR.to_string()),
            StorageWorkerRequest::RecipientLookup {
                address: ADDR.to_string(),
                public_key_registry_contract_id: "CREG".into(),
            },
            StorageWorkerRequest::OperationalFeed {
                limit: 10,
                asp_membership_contract_id: "CASP".into(),
                public_key_registry_contract_id: "CREG".into(),
            },
            StorageWorkerRequest::DeriveASPleaf(AdminASPRequest {
                membership_blinding: stellar_private_payments::types::Field::ZERO,
                pubkey: stellar_private_payments::types::NotePublicKey([0u8; 32]),
            }),
            StorageWorkerRequest::ConfigureTelemetry(WorkerTelemetryConfig {
                level: "info".into(),
                reveal_sensitive: false,
            }),
            StorageWorkerRequest::DumpLogs,
            StorageWorkerRequest::DiagnoseAmbiguousKeypairs {
                account_address: ADDR.to_string(),
            },
        ];
        for request in exceptions {
            assert_eq!(
                request.session_policy(),
                SessionPolicy::Public,
                "expected a documented public exception: {request:?}"
            );
            assert!(
                !request.requires_bound_session(),
                "public exception must stay reachable on the raw surface: {request:?}"
            );
        }
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
    AmbiguousKeypairsDiagnostic(stellar_private_payments::state::AmbiguousKeypairsDiagnostic),
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

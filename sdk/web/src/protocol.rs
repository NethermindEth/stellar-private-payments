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
    gvk::GvkEvent,
    state::BindingVersion,
    types::{
        AspMembershipSync, ContractsEventData, DisclosureReceipt, EncryptionPublicKey, Field,
        KeyDerivationSignature, NotePublicKey, OperationalFeedItem, PortfolioBalance,
        PortfolioPoolEntry, RecipientLookup, SyncMetadata, UserNoteSummary, UserOperation,
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

/// Which key binding a request requires, mirrored across the worker boundary.
///
/// A deployment requires exactly the binding it derives, so this is a function
/// of the deployment's configuration and never a per-user choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredBinding {
    V1,
    V2,
}

impl From<RequiredBinding> for BindingVersion {
    fn from(required: RequiredBinding) -> Self {
        match required {
            RequiredBinding::V1 => BindingVersion::V1,
            RequiredBinding::V2 => BindingVersion::V2,
        }
    }
}

impl From<BindingVersion> for RequiredBinding {
    fn from(version: BindingVersion) -> Self {
        match version {
            BindingVersion::V1 => RequiredBinding::V1,
            BindingVersion::V2 => RequiredBinding::V2,
        }
    }
}

/// Metadata-only answer to "can this account's stored keys be used here?".
///
/// Carries no key material and no address in any variant: it exists so the
/// client and the UI can tell "no keys yet" from "keys exist but were derived
/// for a different deployment configuration" without a status question ever
/// travelling over a route that returns secrets.
// No serde rename: the rest of this protocol crosses the JS boundary with
// variant names as written - StorageWorkerRequest/Response and RequiredBinding
// all do - and the JS side matches on exactly those, so renaming only this
// enum would make every JS comparison silently fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyBindingStatus {
    Absent,
    Acceptable,
    Mismatch { stored: RequiredBinding },
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
    Pause,
    SyncState,
    ProcessPendingState,
    SaveEvents(ContractsEventData),
    SaveSyncProgress {
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    },
    ClearIndexingCursors,
    ClampLastFullyIndexedLedger(u32),
    /// Set the key binding this deployment requires. Sent once by the client
    /// at startup; a later attempt to set a different value is refused, so the
    /// requirement cannot be relaxed by a subsequent request.
    ConfigureBinding(RequiredBinding),
    /// Derive and store an account's privacy keys.
    ///
    /// Deliberately does NOT carry the required binding: the worker takes that
    /// from its own configuration. A caller-supplied value would let a request
    /// select the unverified v1 path on a deployment that requires v2.
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
    /// Metadata-only binding probe. Never returns key material.
    KeyBindingStatus(Address),
    UserNotes(Address, u32),
    PortfolioBalances {
        address: Address,
        enabled_pools: Vec<PortfolioPoolEntry>,
    },
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
    ListPoolGvkEvents {
        pool_contract_id: String,
        after: Option<(u32, String)>,
        limit: u32,
    },
    PoolHasCommitments {
        pool_contract_id: String,
        commitments: Vec<Field>,
    },
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
    KeyBindingStatus(KeyBindingStatus),
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
    PoolGvkEvents(Vec<GvkEvent>),
    PoolHasCommitments(Vec<Field>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerRequest {
    Ping,
    Transact(TransactParams),
    Disclosure(DisclosureProveParams),
    VerifyDisclosureProof(DisclosureReceipt, String),
    ConfigureCircuitsBase(String),
    ConfigureTelemetry(WorkerTelemetryConfig),
    DumpLogs,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerResponse {
    Pong,
    Saved,
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

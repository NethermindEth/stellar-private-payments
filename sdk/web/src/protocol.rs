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
    types::{
        AspMembershipSync, ContractsEventData, DisclosureReceipt, EncryptionKeyPair,
        EncryptionPublicKey, Field, NoteKeyPair, NotePublicKey, OperationalFeedItem,
        PortfolioBalance, PortfolioPoolEntry, RecipientLookup, SyncMetadata, UserNoteSummary,
        UserOperation,
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
pub struct PrivacyKeys {
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
    /// What the database needs before it can be used; see [`StorageStatus`].
    Status,
    /// Open only the public chain cache; leaves the private vault locked.
    OpenPublic,
    WalletContext,
    CreateWallet {
        context: stellar_private_payments::state::wallet_vault::WalletContext,
        secret: UnlockSecret,
    },
    UnlockWallet {
        context: stellar_private_payments::state::wallet_vault::WalletContext,
        secret: UnlockSecret,
    },
    /// Explicitly delete local storage.
    Reset,
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
    SavePrivateKeys(Address, NoteKeyPair, EncryptionKeyPair, Field),
    DisclaimerText,
    DisclaimerState(Address),
    AcceptDisclaimer(Address, String),
    GetSetting(String),
    SetSetting {
        key: String,
        value_json: String,
    },
    PrivacyKeys(Address),
    AspSecret(Address),
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

/// A wallet wrapping secret in a worker message. Debug never shows it and this
/// Rust copy is zeroized on drop; browser message serialization can still make
/// other copies.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnlockSecret(pub String);

impl std::fmt::Debug for UnlockSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockSecret([REDACTED])")
    }
}

impl Drop for UnlockSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// What the local database needs before the app can use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageStatus {
    /// Nothing stored yet: approve wallet setup to create the database.
    New,
    /// An earlier version's unencrypted database: approve wallet setup to
    /// encrypt it.
    Unencrypted,
    /// Set up; approve the enrolled wallet to unlock.
    Locked,
    /// An open operation is still running.
    Opening,
    /// Encrypted data exists without a supported wallet record. Never recreate
    /// implicitly.
    #[serde(rename = "recovery-required")]
    RecoveryRequired,
    /// Open and ready.
    Unlocked,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerResponse {
    Status(StorageStatus),
    WalletContext(Option<stellar_private_payments::state::wallet_vault::WalletContext>),
    Pong,
    SyncState(Vec<SyncMetadata>),
    Saved,
    Error(String),
    DisclaimerState(DisclaimerStatePayload),
    Setting(Option<String>),
    PrivacyKeys(Option<PrivacyKeys>),
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

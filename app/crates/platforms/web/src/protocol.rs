use serde::{Deserialize, Serialize};

pub use stellar_private_payments_sdk::{
    DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams, PreparedProverTx,
    TransactRequest,
};

use stellar_private_payments_sdk::{
    tx::flows::TransactParams,
    types::{
        AspMembershipSync, ContractsEventData, DisclosureReceipt, EncryptionPublicKey, Field,
        KeyDerivationSignature, NotePublicKey, PoolLedgerActivity, PublicKeyEntry, SyncMetadata,
        UserNoteSummary,
    },
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootnodeConfigPayload {
    pub enabled: bool,
    pub url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerRequest {
    Ping,
    SyncState,
    SaveEvents(ContractsEventData),
    SaveSyncProgress {
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    },
    ClearIndexingCursors,
    DeriveSaveUserKeys(Address, KeyDerivationSignature, String),
    DisclaimerState(Address),
    AcceptDisclaimer(Address, String),
    BootnodeConfig,
    SetBootnodeConfig {
        enabled: bool,
        url: String,
    },
    UserKeys(Address),
    AspSecret(Address),
    UserNotes(Address, u32),
    UnspentUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    PoolUserNotes {
        user_address: Address,
        pool_contract_id: Address,
    },
    RecentPoolActivity(u32),
    RecentPubKeys(u32),
    DisclosureInputs(DisclosureInputsRequest),
    Transact(TransactRequest),
    DeriveASPleaf(AdminASPRequest),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerResponse {
    Pong,
    SyncState(Vec<SyncMetadata>),
    Saved,
    Error(String),
    DisclaimerState(DisclaimerStatePayload),
    BootnodeConfig(BootnodeConfigPayload),
    UserKeys(Option<UserKeys>),
    AspSecret(Option<AspSecret>),
    UserNotes(Vec<UserNoteSummary>),
    RecentPoolActivity(Vec<PoolLedgerActivity>),
    PubKeys(Vec<PublicKeyEntry>),
    AspMembershipSync(AspMembershipSync),
    DisclosureInputs(DisclosureInputs),
    TransactParams(TransactParams),
    DeriveASPleaf(Field),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerRequest {
    Ping,
    Transact(TransactParams),
    Disclosure(DisclosureProveParams),
    VerifyDisclosureProof(DisclosureReceipt, String),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerResponse {
    Pong,
    Error(String),
    TransactPrepared(PreparedProverTx),
    Disclosure(DisclosureReceipt),
    DisclosureProofVerified(bool),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminASPRequest {
    pub membership_blinding: Field,
    pub pubkey: NotePublicKey,
}

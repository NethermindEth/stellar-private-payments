use serde::{Deserialize, Serialize};

use prover::flows::{N_OUTPUTS, TransactParams};
pub type Address = String;
use stellar::PreparedSorobanTx;
use types::{
    AspMembershipSync, AspNonMembershipProof, ContractsEventData, DisclosureReceipt, ExtAmount,
    ExtData, Field, KeyDerivationSignature, NoteAmount, NotePrivateKey, NotePublicKey,
    PoolLedgerActivity, PublicKeyEntry, SyncMetadata, UserNoteSummary,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicNoteKeyPair {
    pub public: types::NotePublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicEncryptionKeyPair {
    pub public: types::EncryptionPublicKey,
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
    Disclosure(DisclosureProverRequest),
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
pub struct DisclosureInputsRequest {
    pub user_address: Address,
    pub pool_address: Address,
    pub selected_commitment: Field,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub tree_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureInputs {
    pub root: Field,
    pub note_commitment: Field,
    pub note_amount: NoteAmount,
    pub note_private_key: NotePrivateKey,
    pub note_blinding: Field,
    pub merkle_path_indices: Field,
    pub merkle_path_elements: Vec<Field>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactRequest {
    pub user_address: Address,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub pool_address: Address,
    pub ext_recipient: Address,
    pub ext_amount: ExtAmount,
    pub aspmem_root: Field,
    pub aspmem_contract_id: Address,
    pub aspmem_ledger: u32,
    pub input_commitments: Vec<Field>,
    pub output_amounts: [NoteAmount; N_OUTPUTS],
    pub out_recipient_note_pubkeys: [Option<NotePublicKey>; N_OUTPUTS],
    pub out_recipient_encryption_pubkeys: [Option<types::EncryptionPublicKey>; N_OUTPUTS],
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub non_membership_proof: AspNonMembershipProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTxPublic {
    pub pool_root: Field,
    pub input_nullifiers: [Field; 2],
    pub output_commitments: [Field; 2],
    pub public_amount: Field,
    pub ext_data_hash_be: [u8; 32],
    pub asp_membership_root: Field,
    pub asp_non_membership_root: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedProverTx {
    /// Uncompressed Soroban-ready proof bytes: A(64) || B(128) || C(64) = 256
    /// bytes.
    pub proof_uncompressed: Vec<u8>,
    /// extData passed to the pool contract.
    pub ext_data: ExtData,
    /// Public inputs and derived values used to build the on-chain `Proof`
    /// struct.
    pub prepared: PreparedTxPublic,
    /// Unsigned transaction + auth entries from RPC simulation.
    pub soroban_tx: PreparedSorobanTx,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminASPRequest {
    pub membership_blinding: Field,
    pub pubkey: NotePublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureProverRequest {
    pub inputs: DisclosureInputs,
    pub network: String,
    pub pool_address: String,
    pub authority_label: String,
    pub authority_identity_payload_hex: String,
    pub purpose: String,
    pub context_nonce: Field,
}

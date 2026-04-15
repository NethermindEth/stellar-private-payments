use serde::{Deserialize, Serialize};

use prover::flows::{DepositParams, N_OUTPUTS, TransactParams, TransferParams, WithdrawParams};
pub type Address = String;
use types::{
    AspNonMembershipProof, ContractsEventData, EncryptionKeyPair, EncryptionSignature, ExtAmount,
    ExtData, Field, NoteAmount, NotePublicKey, NoteKeyPair, PublicKeyEntry, SpendingSignature,
    SyncMetadata, AspMembershipSync, UserNoteSummary, PoolLedgerActivity,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeys{
    pub note_keypair: NoteKeyPair,
    pub encryption_keypair: EncryptionKeyPair
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerRequest {
    Ping,
    SyncState,
    SaveEvents(ContractsEventData),
    DeriveSaveUserKeys(Address, SpendingSignature, EncryptionSignature),
    UserKeys(Address),
    UserNotes(Address, u32),
    RecentPoolActivity(u32),
    RecentPubKeys(u32),
    Deposit(DepositRequest),
    Withdraw(WithdrawRequest),
    Transfer(TransferRequest),
    Transact(TransactRequest),
    DeriveASPleaf(AdminASPRequest)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StorageWorkerResponse {
    Pong,
    SyncState(Option<SyncMetadata>),
    Saved,
    Error(String),
    UserKeys(Option<UserKeys>),
    UserNotes(Vec<UserNoteSummary>),
    RecentPoolActivity(Vec<PoolLedgerActivity>),
    PubKeys(Vec<PublicKeyEntry>),
    AspMembershipSync(AspMembershipSync),
    DepositParams(DepositParams),
    WithdrawParams(WithdrawParams),
    TransferParams(TransferParams),
    TransactParams(TransactParams),
    DeriveASPleaf(Field)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerRequest {
    Ping,
    Deposit(DepositParams),
    Withdraw(WithdrawParams),
    Transfer(TransferParams),
    Transact(TransactParams),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProverWorkerResponse {
    Pong,
    Error(String),
    DepositPrepared(DepositPrepared),
    WithdrawPrepared(PreparedProverTx),
    TransferPrepared(PreparedProverTx),
    TransactPrepared(PreparedProverTx),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositRequest{
    pub user_address: Address,
    pub membership_blinding: Field,
    pub amount_stroops: ExtAmount,
    pub pool_root: Option<Field>,
    pub pool_address: Address,
    pub aspmem_root: Field,
    pub aspmem_ledger: u32,
    pub output_amounts: [NoteAmount; N_OUTPUTS],
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub non_membership_proof: AspNonMembershipProof,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawRequest {
    pub user_address: Address,
    pub membership_blinding: Field,
    pub withdraw_recipient: Address,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub aspmem_root: Field,
    pub aspmem_ledger: u32,
    pub input_commitments: Vec<Field>,
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub non_membership_proof: AspNonMembershipProof,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    pub user_address: Address,
    pub membership_blinding: Field,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub pool_address: Address,
    pub aspmem_root: Field,
    pub aspmem_ledger: u32,
    pub input_commitments: Vec<Field>,
    pub output_amounts: [NoteAmount; N_OUTPUTS],
    pub recipient_note_pubkey: NotePublicKey,
    pub recipient_encryption_pubkey: types::EncryptionPublicKey,
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub non_membership_proof: AspNonMembershipProof,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactRequest {
    pub user_address: Address,
    pub membership_blinding: Field,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub pool_address: Address,
    pub ext_recipient: Address,
    pub ext_amount: ExtAmount,
    pub aspmem_root: Field,
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
pub struct DepositPrepared {
    /// Uncompressed Soroban-ready proof bytes: A(64) || B(128) || C(64) = 256 bytes.
    pub proof_uncompressed: Vec<u8>,
    /// extData passed to the pool contract.
    pub ext_data: ExtData,
    /// Public inputs and derived values used to build the on-chain `Proof` struct.
    pub prepared: PreparedTxPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedProverTx {
    /// Uncompressed Soroban-ready proof bytes: A(64) || B(128) || C(64) = 256 bytes.
    pub proof_uncompressed: Vec<u8>,
    /// extData passed to the pool contract.
    pub ext_data: ExtData,
    /// Public inputs and derived values used to build the on-chain `Proof` struct.
    pub prepared: PreparedTxPublic,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminASPRequest{
    pub membership_blinding: Field,
    pub pubkey: NotePublicKey,
}

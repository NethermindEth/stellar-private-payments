pub use ::types::*;

use serde::{Deserialize, Serialize};
use stellar::PreparedSorobanTx;

pub type PreparedTransaction = PreparedSorobanTx;

#[derive(Debug, Clone)]
pub struct PrivatePoolConfig {
    pub rpc_url: String,
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
    pub user_address: String,
    pub storage_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    pub from_ledger: u32,
    pub to_ledger: u32,
    pub new_commitments: u32,
    pub new_nullifiers: u32,
    pub new_membership_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    pub tx_hash: String,
}

#[derive(Debug, Clone)]
pub struct TransferRecipient {
    pub note_public_key: NotePublicKey,
    pub encryption_public_key: EncryptionPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub tx_count: u32,
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub signed_xdr: String,
}

/// Low-level transact inputs; fields will expand as the API is wired up.
#[derive(Debug, Clone)]
pub struct TransactRequest {
    pub amount: NoteAmount,
}

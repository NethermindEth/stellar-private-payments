pub use ::types::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct PrivatePoolConfig {
    pub rpc_url: String,
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
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
pub enum TransferRecipient {
    NotePublicKey(NotePublicKey),
}

impl TransferRecipient {
    pub fn from_note_public_key_hex(hex: &str) -> Result<Self, String> {
        NotePublicKey::parse(hex)
            .map(Self::NotePublicKey)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub step_count: u32,
}

/// Unsigned transaction prepared for external signing (e.g. Freighter).
#[derive(Debug, Clone)]
pub struct PreparedTransaction {
    pub unsigned_xdr: String,
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

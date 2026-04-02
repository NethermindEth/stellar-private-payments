mod chain_data;
pub use chain_data::*;

use serde::{Deserialize, Serialize};

// scripts/deployments.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractConfig {
    pub network: String,
    pub deployer: String,
    pub admin: String,
    // Address of ASP membership deployed contract
    pub asp_membership: String,
    // Address of ASP nonmembership deployed contract
    pub asp_non_membership: String,
    pub verifier: String,
    // Address of Pool deployed contract
    pub pool: String,
    pub initialized: bool,
}

// const dataKeys = ['Admin', 'Token', 'Verifier', 'ASPMembership', 'ASPNonMembership'];
// const merkleKeys = ['Levels', 'CurrentRootIndex', 'NextIndex'];
// maximumDepositAmount
//     results.merkleRoot = formatU256(rootResult.value);
//     results.merkleRootRaw = rootResult.value;

//     if (results.merkleLevels !== undefined) {
//         results.merkleCapacity = Math.pow(2, results.merkleLevels);
//         results.totalCommitments = results.merkleNextIndex || 0;
//     }
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct PoolContractState {

// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ASPMembershipContractState {
//     root
//     root_raw
//     levels
//     next_index
//     admin
//     admin_insert_only // todo safe default to suppose to true if not present
//     capacity:
//     used_slots
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ASPNonMembershipContractState {
//     root
//     root_raw
//     is_empty: bool
//     admin
// }

/// Pool merkle tree leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolLeaf {
    /// Leaf index (primary key).
    pub index: u32,
    /// Commitment hash (hex).
    pub commitment: String,
    /// Ledger sequence when added.
    pub ledger: u32,
}

/// Spent nullifier record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolNullifier {
    /// Nullifier hash (hex, primary key).
    pub nullifier: String,
    /// Ledger sequence when spent.
    pub ledger: u32,
}

/// Encrypted note output from a pool transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEncryptedOutput {
    /// Commitment hash (hex, primary key).
    pub commitment: String,
    /// Leaf index in the pool tree.
    #[serde(rename = "index")]
    pub leaf_index: u32,
    /// Encrypted note bytes (hex).
    #[serde(rename = "encryptedOutput")]
    pub encrypted_output: String,
    /// Ledger sequence when created.
    pub ledger: u32,
}

/// ASP membership tree leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspMembershipLeaf {
    /// Leaf index (primary key).
    pub index: u32,
    /// Leaf hash (hex).
    pub leaf: String,
    /// Tree root after this insertion (hex).
    pub root: String,
    /// Ledger sequence when added.
    pub ledger: u32,
}

/// User note (UTXO).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNote {
    /// Commitment hash (hex, primary key).
    pub id: String,
    /// Owner Stellar address.
    pub owner: String,
    /// Note private key (hex).
    pub private_key: String,
    /// Blinding factor (hex).
    pub blinding: String,
    /// Amount as decimal string.
    pub amount: String,
    /// Leaf index; `None` until mined.
    pub leaf_index: Option<u32>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Ledger sequence when created.
    pub created_at_ledger: u32,
    /// Whether the note has been spent.
    pub spent: bool,
    /// Ledger sequence when spent; `None` if unspent.
    pub spent_at_ledger: Option<u32>,
    /// `true` if received via transfer.
    pub is_received: bool,
}

/// Registered public key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// Stellar address (primary key).
    pub address: String,
    /// X25519 encryption public key (hex).
    pub encryption_key: String,
    /// BN254 note public key (hex).
    pub note_key: String,
    /// Legacy alias for `encryption_key`.
    pub public_key: String,
    /// Ledger sequence when registered.
    pub ledger: u32,
    /// ISO-8601 timestamp when stored locally.
    pub registered_at: String,
}

/// RPC retention window configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionConfig {
    /// RPC endpoint URL (primary key).
    pub rpc_endpoint: String,
    /// Retention window in ledgers.
    pub window: u32,
    /// Human-readable description.
    pub description: String,
    /// Warning threshold in ledgers (80% of `window`).
    pub warning_threshold: u32,
    /// ISO-8601 timestamp when detected.
    pub detected_at: String,
}

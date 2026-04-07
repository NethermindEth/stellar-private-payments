use serde::{Deserialize, Serialize};
use crate::{EncryptionPublicKey, NotePublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractsStateData {
    pub success: bool,
    pub network: String,
    pub pool: PoolInfo,
    pub asp_membership: AspMembership,
    pub asp_non_membership: AspNonMembership,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolInfo {
    pub success: bool,
    pub contract_id: String,
    pub contract_type: String,
    pub admin: String,
    pub token: String,
    pub verifier: String,
    pub aspmembership: String,
    pub aspnonmembership: String,
    pub merkle_levels: u32,
    pub merkle_current_root_index: Option<u32>,
    pub merkle_next_index: String, //num_bigint::BigUint,
    pub maximum_deposit_amount: String, //num_bigint::BigUint,
    pub merkle_root: Option<String>,
    pub merkle_capacity: u64,
    pub total_commitments: String, //num_bigint::BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspMembership {
    pub success: bool,
    pub contract_id: String,
    pub contract_type: String,
    pub root: String,
    pub levels: u32,
    pub next_index: String,
    pub admin: String,
    pub admin_insert_only: bool,
    pub capacity: u64,
    pub used_slots: String, //num_bigint::BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspNonMembership {
    pub success: bool,
    pub contract_id: String,
    pub contract_type: String,
    pub root: String,
    pub is_empty: bool,
    pub admin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a hyphen.
    pub id: String,
    // Sequence number of the ledger in which this event was emitted
    pub ledger: u32,
    // StrKey representation of the contract address that emitted this event.
    pub contract_id: String,
    // The ScVals containing the topics this event was emitted with (as a base64 string).
    pub topics: Vec<String>,
    // The data emitted by the event (an ScVal, serialized as a base64 string).
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractsEventData {
    pub events: Vec<ContractEvent>,
    pub cursor: String
}

/// Per-network sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMetadata {
    /// Sync cursor.
    pub cursor: String,
    /// Last synced ledger.
    pub last_ledger: u32,
}


/// This event allows off-chain observers to track which UTXOs have been spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewNullifierEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a hyphen.
    pub id: String,
    /// The nullifier that was spent, hex
    pub nullifier: String,
}

/// Event emitted when a new commitment is added to the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewCommitmentEvent {
    /// The commitment hash added to the tree, hex
    pub commitment: String,
    /// Index position in the Merkle tree
    pub index: u32,
    /// Encrypted output data (decryptable by the recipient)
    pub encrypted_output: Vec<u8>,
}

/// New pubkey pairs in the pool
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEvent {
    /// Address of the account owner
    pub owner: String,
    /// X25519 encryption public key
    pub encryption_key: EncryptionPublicKey,
    /// BN254 note public key
    pub note_key: NotePublicKey,
}

/// Event emitted when a new leaf is added to the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafAddedEvent {
    /// The leaf value that was inserted, hex
    pub leaf: String,
    /// Index position where the leaf was inserted
    pub index: u64,
    /// New Merkle root after insertion, hex
    pub root: String,
}

/// Event emitted when a new leaf is inserted into the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafInsertedEvent {
    pub key: String,
    pub value: String,
    /// SMT root
    pub root: String,
}

/// Event emitted when a leaf is updated in the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafUpdatedEvent {
    pub key: String,
    pub old_value: String,
    pub new_value: String,
    pub root: String,
}

/// Event emitted when a leaf is deleted in the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafDeletedEvent {
    pub key: String,
    pub root: String,
}

/// A contract event after full parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessedEvent {
    Nullifier(NewNullifierEvent),
    Commitment(NewCommitmentEvent),
    PublicKey(PublicKeyEvent),
    LeafAdded(LeafAddedEvent),
    LeafInserted(LeafInsertedEvent),
    LeafUpdated(LeafUpdatedEvent),
    LeafDeleted(LeafDeletedEvent),
}

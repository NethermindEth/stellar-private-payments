use crate::{EncryptionPublicKey, ExtAmount, Field, NotePublicKey};
use serde::{Deserialize, Serialize};

/// Serde helpers for `[u8; 32]` as a `0x`-prefixed 64-hex string.
///
/// Used by key wrapper types in `crate::lib` via `#[serde(with = "...")]`.
pub(crate) mod serde_0x_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = String::with_capacity(2 + 64);
        out.push_str("0x");
        out.push_str(&hex::encode(bytes));
        serializer.serialize_str(&out)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        if s.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }

        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

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
    /// Network tip (latest ledger observed by the RPC call used to fetch this
    /// state).
    pub ledger: u32,
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
    pub maximum_deposit_amount: ExtAmount,
    pub merkle_root: Option<Field>,
    pub merkle_capacity: u64,
    pub total_commitments: String, //num_bigint::BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspMembership {
    pub success: bool,
    /// Network tip (latest ledger observed by the RPC call used to fetch this
    /// state).
    pub ledger: u32,
    pub contract_id: String,
    pub contract_type: String,
    pub root: Field,
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
    /// Network tip (latest ledger observed by the RPC call used to fetch this
    /// state).
    pub ledger: u32,
    pub contract_id: String,
    pub contract_type: String,
    pub root: Field,
    pub is_empty: bool,
    pub admin: String,
}

/// ASP non-membership (sanctions) proof data needed by the circuit.
///
/// The prover crate does not fetch or build these proofs. Treat them as
/// external inputs provided by a higher-level "state/chain" component.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspNonMembershipProof {
    /// Lookup key (BN254 scalar field element).
    ///
    /// For circuit inputs, convert to little-endian bytes via
    /// `Field::to_le_bytes()`.
    pub key: Field,
    /// Old key (BN254 scalar field element).
    pub old_key: Field,
    /// Old value (BN254 scalar field element).
    pub old_value: Field,
    /// Whether the "old" branch is empty (circuit expects 0/1).
    pub is_old0: bool,
    /// Sibling hashes (SMT proof) as BN254 scalar field elements.
    pub siblings: Vec<Field>,
    /// SMT root (BN254 scalar field element).
    pub root: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
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
    pub cursor: String,
    /// Network tip (latest ledger observed by the RPC call that returned this
    /// batch).
    ///
    /// This advances even when there are no events, and is used as the
    /// authoritative "indexed up to" ledger for precondition checks.
    pub latest_ledger: u32,
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

/// ASP membership sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AspMembershipSync {
    SyncRequired(Option<u32>), // number of ledgers to sync - the gap
    RegisterAtASP,
    UserIndex(u32),
}

/// This event allows off-chain observers to track which UTXOs have been spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewNullifierEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    /// The nullifier that was spent (BN254 field element).
    pub nullifier: Field,
}

/// Event emitted when a new commitment is added to the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewCommitmentEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    /// The commitment hash added to the tree (BN254 field element).
    pub commitment: Field,
    /// Index position in the Merkle tree
    pub index: u32,
    /// Encrypted output data (decryptable by the recipient)
    pub encrypted_output: Vec<u8>,
}

/// New pubkey pairs in the pool
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
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
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    /// The leaf value that was inserted (BN254 field element).
    pub leaf: Field,
    /// Index position where the leaf was inserted
    pub index: u32,
    /// New Merkle root after insertion (BN254 field element).
    pub root: Field,
}

/// Event emitted when a new leaf is inserted into the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafInsertedEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    pub key: Field,
    pub value: Field,
    /// SMT root
    pub root: Field,
}

/// Event emitted when a leaf is updated in the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafUpdatedEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    pub key: Field,
    pub old_value: Field,
    pub new_value: Field,
    pub root: Field,
}

/// Event emitted when a leaf is deleted in the Sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafDeletedEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    pub key: Field,
    pub root: Field,
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

use super::{BabyJubJubPoint, EncryptionPublicKey, ExtAmount, Field, NotePublicKey, PolicyFlags};
use serde::{Deserialize, Serialize};

/// Serde helpers for `[u8; 32]` as a `0x`-prefixed 64-hex string.
///
/// Used by key wrapper types in `super::lib` via `#[serde(with = "...")]`.
pub(crate) mod serde_0x_hex_32 {
    use crate::types::{encode_0x_hex, parse_0x_hex_32};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let out = encode_0x_hex(bytes);
        serializer.serialize_str(&out)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let out = parse_0x_hex_32(&s).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractsStateData {
    pub pools: Vec<PoolInfo>,
    pub asp_membership: AspMembership,
    pub asp_non_membership: AspNonMembership,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolInfo {
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
    pub policy_flags: PolicyFlags,
    /// Admin's Global View Key public point `D`. `None` for pools deployed
    /// from `contracts/pool`.
    /// `Some` for `contracts/pool-gvk` deployments.
    ///
    /// Omitted from serialized output when absent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_view_key: Option<BabyJubJubPoint>,
    /// Global View Key mode (`1` = view-only, `2` = traceable). `None` for
    /// pools deployed from `contracts/pool`
    /// Omitted from serialized output when absent, as for `admin_view_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gvk_mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspMembership {
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
    /// Network tip (latest ledger observed by the RPC call used to fetch this
    /// state).
    pub ledger: u32,
    pub contract_id: String,
    pub contract_type: String,
    pub root: Field,
    pub is_empty: bool,
    pub admin: String,
}

/// ASP non-membership (blocklist) proof data needed by the circuit.
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

/// On-chain anchors required to build a pool `transact` witness.
#[derive(Debug, Clone)]
pub struct TransactChainContext {
    pub pool_root: Field,
    pub pool_next_index: u32,
    pub pool_merkle_levels: u32,
    pub asp_membership_levels: u32,
    pub asp_membership_root: Field,
    pub asp_membership_contract_id: String,
    pub asp_membership_ledger: u32,
    pub non_membership_proof: Option<AspNonMembershipProof>,
    pub policy_flags: PolicyFlags,
}

pub fn transact_chain_context_from_state(
    data: ContractsStateData,
    pool_contract_id: &str,
    non_membership_proof: Option<AspNonMembershipProof>,
) -> anyhow::Result<TransactChainContext> {
    let pool = data
        .pools
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("pool data not fetched for {pool_contract_id}"))?;
    let pool_root = pool
        .merkle_root
        .ok_or_else(|| anyhow::anyhow!("pool merkle_root not fetched"))?;
    let pool_next_index = pool
        .merkle_next_index
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid pool merkle_next_index: {e}"))?;

    Ok(TransactChainContext {
        pool_root,
        pool_next_index,
        pool_merkle_levels: pool.merkle_levels,
        asp_membership_levels: data.asp_membership.levels,
        asp_membership_root: data.asp_membership.root,
        asp_membership_contract_id: data.asp_membership.contract_id,
        asp_membership_ledger: data.asp_membership.ledger,
        non_membership_proof,
        policy_flags: pool.policy_flags,
    })
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

/// Per-pool sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMetadata {
    /// Pool contract id (C...).
    pub contract_id: String,
    /// Sync cursor.
    pub cursor: String,
    /// Highest ledger seen in saved pages (resume watermark).
    pub last_indexed_ledger: u32,
    /// Ledger through which catch-up is proven (empty page at tip).
    pub last_fully_indexed_ledger: u32,
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

#[cfg(test)]
mod pool_info_gvk_tests {
    use super::*;
    use crate::types::U256;

    fn pool_info_with_gvk() -> PoolInfo {
        PoolInfo {
            ledger: 42,
            contract_id: "CPOOL".to_string(),
            contract_type: "Privacy Pool".to_string(),
            admin: "GADMIN".to_string(),
            token: "CTOKEN".to_string(),
            verifier: "CVERIFIER".to_string(),
            aspmembership: "CASPM".to_string(),
            aspnonmembership: "CASPN".to_string(),
            merkle_levels: 20,
            merkle_current_root_index: Some(3),
            merkle_next_index: "6".to_string(),
            maximum_deposit_amount: ExtAmount::from(1_000i128),
            merkle_root: Some(Field(U256::from(7))),
            merkle_capacity: 1_048_576,
            total_commitments: "6".to_string(),
            policy_flags: PolicyFlags::EMPTY,
            admin_view_key: Some(BabyJubJubPoint {
                x: Field(U256::from(1)),
                y: Field(U256::from(2)),
            }),
            gvk_mode: Some(2),
        }
    }

    /// State serialized before the GVK fields existed must still decode.
    ///
    /// `skip_serializing_if` makes this the *normal* path rather than a
    /// legacy one: every non-GVK pool now round-trips through JSON with both
    /// keys absent, so this covers current output as much as old output.
    #[test]
    fn pool_info_decodes_json_written_before_the_gvk_fields_existed() {
        let mut value =
            serde_json::to_value(pool_info_with_gvk()).expect("serialize PoolInfo to value");
        let object = value
            .as_object_mut()
            .expect("PoolInfo serializes as object");
        assert!(object.remove("adminViewKey").is_some(), "field was present");
        assert!(object.remove("gvkMode").is_some(), "field was present");

        let decoded: PoolInfo = serde_json::from_value(value).expect("decode pre-GVK PoolInfo");

        assert!(decoded.admin_view_key.is_none());
        assert!(decoded.gvk_mode.is_none());
        assert_eq!(decoded.contract_id, "CPOOL");
        assert_eq!(decoded.merkle_levels, 20);
    }

    #[test]
    fn pool_info_round_trips_with_gvk_fields_set() {
        let pool = pool_info_with_gvk();
        let encoded = serde_json::to_string(&pool).expect("serialize PoolInfo");
        let decoded: PoolInfo = serde_json::from_str(&encoded).expect("decode PoolInfo");

        assert_eq!(decoded.admin_view_key, pool.admin_view_key);
        assert_eq!(decoded.gvk_mode, pool.gvk_mode);
    }

    /// A `contracts/pool` deployment must emit no GVK keys at all, rather
    /// than nulls a consumer would have to distinguish from a real value.
    #[test]
    fn pool_info_omits_gvk_keys_for_a_non_gvk_pool() {
        let pool = PoolInfo {
            admin_view_key: None,
            gvk_mode: None,
            ..pool_info_with_gvk()
        };

        let value = serde_json::to_value(&pool).expect("serialize PoolInfo to value");
        let object = value.as_object().expect("PoolInfo serializes as object");

        assert!(!object.contains_key("adminViewKey"));
        assert!(!object.contains_key("gvkMode"));
        // Unrelated optional fields keep their existing null-emitting shape.
        assert!(object.contains_key("merkleRoot"));
        assert!(object.contains_key("merkleCurrentRootIndex"));

        let decoded: PoolInfo = serde_json::from_value(value).expect("decode non-GVK PoolInfo");
        assert!(decoded.admin_view_key.is_none());
        assert!(decoded.gvk_mode.is_none());
    }
}

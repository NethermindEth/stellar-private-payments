use serde::{Deserialize, Serialize};

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

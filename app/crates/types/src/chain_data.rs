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
    pub id: String,
    pub ledger: u32,
    pub typ: String,
    pub contract_id: String,
    pub topic: String,
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

use futures::try_join;
use anyhow::{anyhow, Result, Context};
use log::{info, error, debug};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stellar::{scval_to_address_string, scval_to_u32, scval_to_u256, scval_to_u64, scval_to_bool};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractsData {
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

// {
//   "success": true,
//   "network": "testnet",
//   "timestamp": "2026-04-01T00:39:54.714Z",
//   "pool": {
//     "success": true,
//     "contractId": "CA2TZYEXHGWWJJYYETDQBAUNJF7F2J4GVLDLW6LM5W32IIT4AO5SMPWQ",
//     "contractType": "Privacy Pool",
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL",
//     "token": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
//     "verifier": "CD3S2BFTZP7HIF7CKOAA5UUZEKL4WDTUDJOIPQAMTWF6QHYFRYCIGA6U",
//     "aspmembership": "CAC7YUZGC65TXX4I6LGBUVGEZW767LAP5JVZT5O2I6DIA3NGL6WKQOGH",
//     "aspnonmembership": "CBVFZJBBASMAOXWFQ63IZPQHFES7MZNB5ZAPE2CR2KLJD3DNTFTN4REX",
//     "merkleLevels": 10,
//     "merkleCurrentRootIndex": 5,
//     "merkleNextIndex": "10",
//     "maximumDepositAmount": "1000000000",
//     "merkleRoot": "0x20e8f01004bcd8822c0f4da57b156b2c7015ff10c7830aae1397cc045b8c650e",
//     "merkleRootRaw": "14885576524674421798718372801588381750575651689391702400183312580099508561166",
//     "merkleCapacity": 1024,
//     "totalCommitments": "10"
//   },
//   "aspMembership": {
//     "success": true,
//     "contractId": "CAC7YUZGC65TXX4I6LGBUVGEZW767LAP5JVZT5O2I6DIA3NGL6WKQOGH",
//     "contractType": "ASP Membership",
//     "root": "0x08c1475ba440b720e627897ed8dbed1712a88d5e0b4cc56501f81bc501747d0e",
//     "rootRaw": "3959996766811966306066542215696728549545304777615549736881113009222598294798",
//     "levels": 10,
//     "nextIndex": "1",
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL",
//     "adminInsertOnly": true,
//     "capacity": 1024,
//     "usedSlots": "1"
//   },
//   "aspNonMembership": {
//     "success": true,
//     "contractId": "CBVFZJBBASMAOXWFQ63IZPQHFES7MZNB5ZAPE2CR2KLJD3DNTFTN4REX",
//     "contractType": "ASP Non-Membership (Sparse Merkle Tree)",
//     "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
//     "rootRaw": "0",
//     "isEmpty": true,
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL"
//   }
// }


macro_rules! get_state {
    ($map:expr, $key:expr, $source:expr) => {
        $map.get($key).ok_or_else(|| {
            anyhow::anyhow!(
                "missing {} state key in the contract {:?}",
                $key,
                $source
            )
        })
    };
}

// TODO(Maks) readAllContractStates
pub async fn all_contracts_data(client: &stellar::Client, config: &types::ContractConfig) -> Result<ContractsData> {
    let (pool_state, asp_membership_state, asp_non_membership_state) = try_join!(
        client.get_contract_data(&config.pool, &["Admin", "Token", "Verifier", "ASPMembership", "ASPNonMembership", "Levels", "CurrentRootIndex", "NextIndex", "MaximumDepositAmount"], &[]),
        client.get_contract_data(&config.asp_membership, &["Root", "Levels", "NextIndex", "Admin", "AdminInsertOnly"], &[]),
        client.get_contract_data(&config.asp_non_membership, &["Root", "Admin"], &[]),
    )?;

    let (merkle_current_root_index, merkle_root) = if let Some(current_roout_index) = pool_state.get("CurrentRootIndex") {
        let merkle_current_root_index = scval_to_u32(current_roout_index)?;
        let state = client.get_contract_data(&config.pool, &[], &[("Root", merkle_current_root_index)]).await?;
         (Some(merkle_current_root_index), Some(scval_to_u256(get_state!(state, "Root", config.pool)?)?))
    } else {
        (None, None)
    };

    let merkle_levels = scval_to_u32(get_state!(pool_state, "Levels", config.pool)?)?;
    let merkle_capacity = 2u64.pow(merkle_levels);
    let merkle_next_index = scval_to_u64(get_state!(pool_state, "NextIndex", config.pool)?)?;

    let pool = PoolInfo {
        success: true,
        contract_id: config.pool.clone(),
        contract_type: "Privacy Pool".to_string(),
        admin: scval_to_address_string(get_state!(pool_state, "Admin", config.pool)?)?,
        token: scval_to_address_string(get_state!(pool_state, "Token", config.pool)?)?,
        verifier: scval_to_address_string(get_state!(pool_state, "Verifier", config.pool)?)?,
        aspmembership: scval_to_address_string(get_state!(pool_state, "ASPMembership", config.pool)?)?,
        aspnonmembership: scval_to_address_string(get_state!(pool_state, "ASPNonMembership", config.pool)?)?,
        merkle_levels,
        merkle_current_root_index,
        merkle_next_index: merkle_next_index.to_string(),
        maximum_deposit_amount: scval_to_u256(get_state!(pool_state, "MaximumDepositAmount", config.pool)?)?.to_string(),
        merkle_root: merkle_root.map(|r| format!("0x{:064x}", r)),
        merkle_capacity,
        total_commitments: merkle_next_index.to_string(),
    };

    let asp_mem_next_index = scval_to_u64(get_state!(asp_membership_state, "NextIndex", config.asp_membership)?)?;
    let asp_mem_levels = scval_to_u32(get_state!(asp_membership_state, "Levels", config.asp_membership)?)?;
    let asp_mem_capacity = 2u64.pow(asp_mem_levels);

    let asp_membership = AspMembership {
        success: true,
        contract_id: config.asp_membership.clone(),
        contract_type: "ASP Membership".to_string(),
        root: format!("0x{:064x}", scval_to_u256(get_state!(asp_membership_state, "Root", config.asp_membership)?)?),
        levels: asp_mem_levels,
        next_index: asp_mem_next_index.to_string(),
        admin: scval_to_address_string(get_state!(asp_membership_state, "Admin", config.asp_membership)?)?,
        admin_insert_only: scval_to_bool(get_state!(asp_membership_state, "AdminInsertOnly", config.asp_membership)?)?,
        capacity: asp_mem_capacity,
        used_slots: asp_mem_next_index.to_string(),
    };

    let asp_nonmem_root = scval_to_u256(get_state!(asp_non_membership_state, "Root", config.asp_non_membership)?)?;
    let asp_non_membership = AspNonMembership {
        success: true,
        contract_id: config.asp_non_membership.clone(),
        contract_type: "ASP Non-Membership (Sparse Merkle Tree)".to_string(),
        root: format!("0x{:064x}", asp_nonmem_root),
        is_empty: asp_nonmem_root.is_zero(),
        admin: scval_to_address_string(get_state!(asp_non_membership_state, "Admin", config.asp_non_membership)?)?,
    };


    let data = ContractsData {
        success: true,
        network: "testnet".to_string(),
        pool,
        asp_membership,
        asp_non_membership,
    };

    Ok(data)
}

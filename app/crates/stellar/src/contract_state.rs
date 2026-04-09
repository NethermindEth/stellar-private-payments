use futures::try_join;
use anyhow::{Result, anyhow};
use crate::rpc::Client;
use crate::conversions::{scval_to_address_string, scval_to_u32, scval_to_u256, scval_to_u64, scval_to_bool};
use crate::DEPLOYMENT;
use types::ContractConfig;
use types::{PoolInfo, AspMembership, AspNonMembership, ContractsStateData, ExtAmount, Field, U256};

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

pub struct StateFetcher {
    client: Client,
    config: ContractConfig
}

impl StateFetcher {

    fn u256_to_i128_checked(v: U256, what: &'static str) -> Result<i128> {
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);

        // Must fit into 128 bits to be representable as i128.
        if be[..16].iter().any(|&b| b != 0) {
            return Err(anyhow!("{what} does not fit into i128"));
        }

        let mut low_bytes = [0u8; 16];
        low_bytes.copy_from_slice(&be[16..]);
        let low = u128::from_be_bytes(low_bytes);

        if low > i128::MAX as u128 {
            return Err(anyhow!("{what} does not fit into i128"));
        }

        Ok(low as i128)
    }

    pub fn new(rpc_url: &str) -> Result<Self> {
        let config: ContractConfig = serde_json::from_str(DEPLOYMENT)?;
        Ok(Self {
            client: Client::new(rpc_url)?,
            config
        })
    }

    pub async fn pool_contract_state(&self) -> Result<PoolInfo> {
        let pool_state = self.client.get_contract_data(&self.config.pool, &["Admin", "Token", "Verifier", "ASPMembership", "ASPNonMembership", "Levels", "CurrentRootIndex", "NextIndex", "MaximumDepositAmount"], &[]).await?;
        let (merkle_current_root_index, merkle_root) = if let Some(current_roout_index) = pool_state.get("CurrentRootIndex") {
            let merkle_current_root_index = scval_to_u32(current_roout_index)?;
            let state = self.client.get_contract_data(&self.config.pool, &[], &[("Root", merkle_current_root_index)]).await?;
            (Some(merkle_current_root_index), Some(scval_to_u256(get_state!(state, "Root", self.config.pool)?)?))
        } else {
            (None, None)
        };

        let merkle_levels = scval_to_u32(get_state!(pool_state, "Levels", self.config.pool)?)?;
        let merkle_capacity = 2u64.pow(merkle_levels);
        let merkle_next_index = scval_to_u64(get_state!(pool_state, "NextIndex", self.config.pool)?)?;
        let maximum_deposit_amount_u256 =
            scval_to_u256(get_state!(pool_state, "MaximumDepositAmount", self.config.pool)?)?;
        let maximum_deposit_amount = ExtAmount::from(Self::u256_to_i128_checked(
            maximum_deposit_amount_u256,
            "maximum_deposit_amount",
        )?);
        let merkle_root = merkle_root
            .map(Field::try_from_u256)
            .transpose()?;

        let pool = PoolInfo {
            success: true,
            contract_id: self.config.pool.clone(),
            contract_type: "Privacy Pool".to_string(),
            admin: scval_to_address_string(get_state!(pool_state, "Admin", self.config.pool)?)?,
            token: scval_to_address_string(get_state!(pool_state, "Token", self.config.pool)?)?,
            verifier: scval_to_address_string(get_state!(pool_state, "Verifier", self.config.pool)?)?,
            aspmembership: scval_to_address_string(get_state!(pool_state, "ASPMembership", self.config.pool)?)?,
            aspnonmembership: scval_to_address_string(get_state!(pool_state, "ASPNonMembership", self.config.pool)?)?,
            merkle_levels,
            merkle_current_root_index,
            merkle_next_index: merkle_next_index.to_string(),
            maximum_deposit_amount,
            merkle_root,
            merkle_capacity,
            total_commitments: merkle_next_index.to_string(),
        };
        Ok(pool)
    }

    pub async fn asp_membership_contract_state(&self) -> Result<AspMembership> {
        let asp_membership_state = self.client.get_contract_data(&self.config.asp_membership, &["Root", "Levels", "NextIndex", "Admin", "AdminInsertOnly"], &[]).await?;
        let asp_mem_next_index = scval_to_u64(get_state!(asp_membership_state, "NextIndex", self.config.asp_membership)?)?;
        let asp_mem_levels = scval_to_u32(get_state!(asp_membership_state, "Levels", self.config.asp_membership)?)?;
        let asp_mem_capacity = 2u64.pow(asp_mem_levels);
        let root_u256 = scval_to_u256(get_state!(asp_membership_state, "Root", self.config.asp_membership)?)?;
        let root = Field::try_from_u256(root_u256)?;

        let asp_membership = AspMembership {
            success: true,
            contract_id: self.config.asp_membership.clone(),
            contract_type: "ASP Membership".to_string(),
            root,
            levels: asp_mem_levels,
            next_index: asp_mem_next_index.to_string(),
            admin: scval_to_address_string(get_state!(asp_membership_state, "Admin", self.config.asp_membership)?)?,
            admin_insert_only: scval_to_bool(get_state!(asp_membership_state, "AdminInsertOnly", self.config.asp_membership)?)?,
            capacity: asp_mem_capacity,
            used_slots: asp_mem_next_index.to_string(),
        };
        Ok(asp_membership)
    }

    pub async fn asp_nonmembership_contract_state(&self) -> Result<AspNonMembership> {
        let asp_non_membership_state = self.client.get_contract_data(&self.config.asp_non_membership, &["Root", "Admin"], &[]).await?;
            let asp_nonmem_root_u256 = scval_to_u256(get_state!(asp_non_membership_state, "Root", self.config.asp_non_membership)?)?;
            let asp_nonmem_root = Field::try_from_u256(asp_nonmem_root_u256)?;
            let asp_non_membership = AspNonMembership {
                success: true,
                contract_id: self.config.asp_non_membership.clone(),
                contract_type: "ASP Non-Membership (Sparse Merkle Tree)".to_string(),
                root: asp_nonmem_root,
                is_empty: asp_nonmem_root.as_u256() == U256::from(0u64),
                admin: scval_to_address_string(get_state!(asp_non_membership_state, "Admin", self.config.asp_non_membership)?)?,
            };
        Ok(asp_non_membership)
    }

    pub async fn all_contracts_data(&self) -> Result<ContractsStateData> {
        let (pool, asp_membership, asp_non_membership) = try_join!(
            self.pool_contract_state(),
            self.asp_membership_contract_state(),
            self.asp_nonmembership_contract_state(),
        )?;

        let data = ContractsStateData {
            success: true,
            network: "testnet".to_string(),
            pool,
            asp_membership,
            asp_non_membership,
        };

        Ok(data)
    }
}

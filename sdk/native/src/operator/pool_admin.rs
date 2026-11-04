use crate::{Error, chain::RpcClient, types::ContractConfig};

use super::{AdminState, ensure_listed, pool_ids, read_admin};

/// Session for the admin of one pool.
///
/// Open with [`crate::Client::pool_admin`].
pub struct PoolAdmin {
    rpc: RpcClient,
    contract_config: ContractConfig,
    contract_id: String,
}

impl PoolAdmin {
    /// Opens a session over `rpc_url` for one of the deployment's
    /// `pool_ids`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidConfig`] for any other contract.
    pub fn open(
        rpc_url: &str,
        contract_config: ContractConfig,
        contract_id: &str,
    ) -> Result<Self, Error> {
        Self::new(RpcClient::new(rpc_url)?, contract_config, contract_id)
    }

    pub(crate) fn new(
        rpc: RpcClient,
        contract_config: ContractConfig,
        contract_id: &str,
    ) -> Result<Self, Error> {
        ensure_listed(&pool_ids(&contract_config), contract_id, "pool")?;
        Ok(Self {
            rpc,
            contract_config,
            contract_id: contract_id.to_string(),
        })
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Admin and pending admin of the pool.
    pub async fn admin(&self) -> Result<AdminState, Error> {
        read_admin(&self.rpc, &self.contract_config, &self.contract_id).await
    }
}

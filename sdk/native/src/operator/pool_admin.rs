use crate::{Error, chain::RpcClient, types::ContractConfig};

use super::{AdminState, read_admin};

/// Session for the admin of one pool.
///
/// Open with [`crate::Client::pool_admin`].
pub struct PoolAdmin {
    rpc: RpcClient,
    contract_config: ContractConfig,
    contract_id: String,
}

impl PoolAdmin {
    pub(crate) fn new(
        rpc: RpcClient,
        contract_config: ContractConfig,
        contract_id: String,
    ) -> Self {
        Self {
            rpc,
            contract_config,
            contract_id,
        }
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Admin and pending admin of the pool.
    pub async fn admin(&self) -> Result<AdminState, Error> {
        read_admin(&self.rpc, &self.contract_config, &self.contract_id).await
    }
}

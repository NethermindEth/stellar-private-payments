use crate::{
    Error,
    chain::{RpcClient, StateFetcher},
    types::{AspMembership, ContractConfig},
};

use super::{AdminState, read_admin};

/// Session for the admin of one membership tree.
///
/// Open with [`crate::Client::allowlist_operator`].
pub struct AllowlistOperator {
    rpc: RpcClient,
    contract_config: ContractConfig,
    contract_id: String,
}

impl AllowlistOperator {
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

    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspMembership, Error> {
        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())?;
        Ok(fetcher.asp_membership_state(&self.contract_id).await?)
    }

    /// Admin and pending admin of the tree.
    pub async fn admin(&self) -> Result<AdminState, Error> {
        read_admin(&self.rpc, &self.contract_config, &self.contract_id).await
    }
}

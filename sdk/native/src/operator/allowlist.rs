use crate::{
    Error,
    chain::{RpcClient, StateFetcher},
    types::{AspMembership, ContractConfig},
};

use super::{AdminState, allowlist_ids, ensure_listed, read_admin};

/// Session for the admin of one membership tree.
///
/// Open with [`crate::Client::allowlist_operator`].
pub struct AllowlistOperator {
    rpc: RpcClient,
    contract_config: ContractConfig,
    contract_id: String,
}

impl AllowlistOperator {
    /// Opens a session over `rpc_url` for one of the deployment's
    /// `allowlist_ids`.
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
        ensure_listed(
            &allowlist_ids(&contract_config),
            contract_id,
            "membership tree",
        )?;
        Ok(Self {
            rpc,
            contract_config,
            contract_id: contract_id.to_string(),
        })
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

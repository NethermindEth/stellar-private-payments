use crate::{Error, chain::RpcClient, types::ContractConfig};

use super::{AdminState, UnsignedOperatorCall, address_arg, ensure_listed, pool_ids, read_admin};

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

    /// Proposes `new_admin` as the pool's admin, sourced by its current
    /// admin. The new admin takes over once it calls [`Self::accept_admin`].
    pub async fn propose_admin(&self, new_admin: &str) -> Result<UnsignedOperatorCall, Error> {
        let new_admin = address_arg(new_admin)?;
        self.admin_call("update_admin", vec![new_admin]).await
    }

    /// Withdraws the pending admin transfer, sourced by the current admin.
    pub async fn cancel_admin_transfer(&self) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("cancel_admin_transfer", Vec::new()).await
    }

    /// Completes the pending admin transfer, sourced by the pending admin.
    pub async fn accept_admin(&self) -> Result<UnsignedOperatorCall, Error> {
        super::accept_admin(&self.rpc, &self.contract_config, &self.contract_id).await
    }

    /// Points the pool at membership tree `tree`, sourced by the pool admin.
    /// The pool refuses a tree that does not run its allowlist code.
    pub async fn repoint_allowlist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        let tree = address_arg(tree)?;
        self.admin_call("update_asp_membership", vec![tree]).await
    }

    /// Points the pool at non-membership tree `tree`, sourced by the pool
    /// admin. The pool refuses a tree that does not run its blocklist code.
    pub async fn repoint_blocklist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        let tree = address_arg(tree)?;
        self.admin_call("update_asp_non_membership", vec![tree])
            .await
    }

    /// Stops deposits; transfers and withdrawals continue.
    pub async fn pause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("pause_deposits", Vec::new()).await
    }

    pub async fn unpause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("unpause_deposits", Vec::new()).await
    }

    async fn admin_call(
        &self,
        method: &str,
        args: Vec<stellar_xdr::ScVal>,
    ) -> Result<UnsignedOperatorCall, Error> {
        super::admin_call(
            &self.rpc,
            &self.contract_config,
            &self.contract_id,
            method,
            args,
        )
        .await
    }
}

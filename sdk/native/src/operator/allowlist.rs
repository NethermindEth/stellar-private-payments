use crate::{
    Error,
    chain::{RpcClient, StateFetcher, field_to_scval_u256},
    types::{AspMembership, ContractConfig, Field},
};

use super::{
    AdminState, UnsignedOperatorCall, address_arg, allowlist_ids, ensure_listed, read_admin,
};

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

    /// Proposes `new_admin` as the tree's admin, sourced by its current
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

    /// Appends `leaf` to the tree, sourced by its admin. Derive a user's leaf
    /// with [`super::derive_asp_user_leaf`].
    pub async fn insert_leaf(&self, leaf: Field) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("insert_leaf", vec![field_to_scval_u256(leaf)])
            .await
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

use crate::{
    Error,
    chain::{StateFetcher, field_to_scval_u256},
    types::{AspMembership, Field},
};

use super::UnsignedOperatorCall;

contract_handle! {
    /// Session for the admin of one membership tree.
    ///
    /// Open with [`crate::Client::allowlist_operator`] or [`Self::open`].
    AllowlistOperator, allowlist_ids
}

impl AllowlistOperator {
    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspMembership, Error> {
        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())?;
        Ok(fetcher.asp_membership_state(&self.contract_id).await?)
    }

    /// Appends `leaf` to the tree, sourced by its admin. Derive a user's leaf
    /// with [`super::derive_asp_user_leaf`].
    pub async fn insert_leaf(&self, leaf: Field) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("insert_leaf", vec![field_to_scval_u256(leaf)])
            .await
    }
}

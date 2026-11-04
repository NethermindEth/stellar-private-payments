use crate::Error;

use super::{UnsignedOperatorCall, address_arg};

contract_handle! {
    /// Session for the admin of one pool.
    ///
    /// Open with [`crate::Client::pool_admin`] or [`Self::open`].
    PoolAdmin, pool_ids
}

impl PoolAdmin {
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
}

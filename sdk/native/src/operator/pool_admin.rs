use std::collections::HashMap;

use anyhow::anyhow;
use stellar_xdr as xdr;

use crate::{
    Error,
    chain::{ContractDataBulkRequest, scval_to_address_string, scval_to_policy_flags},
    types::PolicyFlags,
};

use super::{UnsignedOperatorCall, address_arg};

/// The trees a pool reads, and the policy that decides which of them its
/// proofs use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolLists {
    pub allowlist: String,
    pub blocklist: String,
    pub policy_flags: PolicyFlags,
}

impl PoolLists {
    /// Whether the pool's proofs use its allowlist.
    pub fn uses_allowlist(&self) -> bool {
        self.policy_flags.requires_membership_proofs()
    }

    /// Whether the pool's proofs use its blocklist.
    pub fn uses_blocklist(&self) -> bool {
        self.policy_flags.requires_non_membership_proofs()
    }

    fn from_instance(pool: &str, state: &HashMap<String, xdr::ScVal>) -> Result<Self, Error> {
        let get = |key: &str| {
            state
                .get(key)
                .ok_or_else(|| anyhow!("pool {pool} has no {key} in its instance storage"))
        };
        Ok(Self {
            allowlist: scval_to_address_string(get("ASPMembership")?)?,
            blocklist: scval_to_address_string(get("ASPNonMembership")?)?,
            policy_flags: scval_to_policy_flags(get("PolicyFlags")?)?,
        })
    }
}

contract_handle! {
    /// Session for the admin of one pool.
    ///
    /// Open with [`crate::Client::pool_admin`] or [`Self::open`].
    PoolAdmin, pool_ids
}

impl PoolAdmin {
    /// The trees the pool reads, which a re-point changes and the deployment
    /// config does not follow.
    pub async fn lists(&self) -> Result<PoolLists, Error> {
        let (state, _) = self
            .rpc
            .get_contract_data_bulk(&[ContractDataBulkRequest {
                contract_id: &self.contract_id,
                enum_keys: Vec::new(),
            }])
            .await?;
        let empty = HashMap::new();
        PoolLists::from_instance(
            &self.contract_id,
            state.get(&self.contract_id).unwrap_or(&empty),
        )
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

    fn instance(flags: u32) -> HashMap<String, xdr::ScVal> {
        let tree = xdr::ScVal::Address(TREE.parse().expect("address"));
        HashMap::from([
            ("ASPMembership".to_string(), tree.clone()),
            ("ASPNonMembership".to_string(), tree),
            ("PolicyFlags".to_string(), xdr::ScVal::U32(flags)),
        ])
    }

    #[test]
    fn lists_are_read_from_the_instance() {
        let lists = PoolLists::from_instance("pool", &instance(PolicyFlags::BLOCKLIST.bits()))
            .expect("lists");
        assert_eq!(lists.allowlist, TREE);
        assert_eq!(lists.blocklist, TREE);
        assert!(!lists.uses_allowlist());
        assert!(lists.uses_blocklist());
    }

    #[test]
    fn a_missing_list_is_an_error() {
        let mut state = instance(0);
        state.remove("ASPNonMembership");
        let err = PoolLists::from_instance("pool", &state).expect_err("missing blocklist");
        assert!(err.to_string().contains("ASPNonMembership"), "{err}");
    }
}

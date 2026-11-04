//! Operator API, one handle per administered contract.
//!
//! - [`AllowlistOperator`]: the admin of one membership tree.
//! - [`BlocklistOperator`]: the admin of one non-membership tree.
//! - [`PoolAdmin`]: the admin of one pool.
//! - [`GvkAuthority`]: the holder of a Global View Key private key.
//!
//! Every contract may have a different admin. None of the handles needs a
//! user account, signer or prover. The contract handles need no storage
//! either: open them with `open(rpc_url, config, contract_id)` or from
//! [`crate::Client`].

mod allowlist;
mod blocklist;
mod gvk;
mod pool_admin;

use stellar_xdr as xdr;

use crate::{
    Error,
    chain::{RpcClient, scval_to_address_string},
    types::ContractConfig,
};

pub use crate::crypto::derive_asp_user_leaf;
pub use allowlist::AllowlistOperator;
pub use blocklist::BlocklistOperator;
pub use gvk::GvkAuthority;
pub use pool_admin::PoolAdmin;

/// A contract's admin and the admin proposed to replace it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminState {
    pub admin: String,
    /// Set between `update_admin` and `accept_admin` or
    /// `cancel_admin_transfer`.
    pub pending_admin: Option<String>,
}

/// Membership trees of the deployment, `asp_membership` first, then the added
/// ones in config order.
pub fn allowlist_ids(config: &ContractConfig) -> Vec<String> {
    std::iter::once(config.asp_membership.clone())
        .chain(
            config
                .added_asp_memberships
                .iter()
                .map(|tree| tree.contract_id.clone()),
        )
        .collect()
}

/// Non-membership trees of the deployment.
pub fn blocklist_ids(config: &ContractConfig) -> Vec<String> {
    vec![config.asp_non_membership.clone()]
}

/// Pools of the deployment, enabled or not, in config order.
pub fn pool_ids(config: &ContractConfig) -> Vec<String> {
    config
        .pools
        .iter()
        .map(|pool| pool.pool_contract_id.clone())
        .collect()
}

/// Refuses a `contract_id` that is not one of `ids`, the deployment's
/// contracts of kind `kind`.
pub(crate) fn ensure_listed(ids: &[String], contract_id: &str, kind: &str) -> Result<(), Error> {
    if ids.iter().any(|id| id == contract_id) {
        Ok(())
    } else {
        Err(Error::InvalidConfig(format!(
            "{contract_id} is not a {kind} of this deployment"
        )))
    }
}

/// Reads `get_admin` and `get_pending_admin` from `contract_id` by simulation.
async fn read_admin(
    rpc: &RpcClient,
    config: &ContractConfig,
    contract_id: &str,
) -> Result<AdminState, Error> {
    let source = &config.deployer;
    let admin = rpc
        .read_contract(contract_id, source, "get_admin", Vec::new())
        .await?;
    let pending = rpc
        .read_contract(contract_id, source, "get_pending_admin", Vec::new())
        .await?;
    Ok(AdminState {
        admin: scval_to_address_string(&admin)?,
        pending_admin: match pending {
            xdr::ScVal::Void => None,
            address => Some(scval_to_address_string(&address)?),
        },
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod test_support {
    use crate::{
        Client, StorageHandle,
        types::{
            AssetDescriptor, ContractConfig, GvkMode, PolicyFlags, PoolConfigEntry, TreeConfigEntry,
        },
    };

    pub const POOL: &str = "pool";
    pub const MEMBERSHIP: &str = "membership";
    pub const ADDED_MEMBERSHIP: &str = "added-membership";
    pub const NON_MEMBERSHIP: &str = "non-membership";

    pub fn config() -> ContractConfig {
        ContractConfig {
            network_passphrase: None,
            rpc_url: None,
            network: "Test SDF Network ; September 2015".to_string(),
            kdf_domain: String::new(),
            deployer: String::new(),
            admin: String::new(),
            asp_membership: MEMBERSHIP.to_string(),
            added_asp_memberships: vec![TreeConfigEntry {
                contract_id: ADDED_MEMBERSHIP.to_string(),
                deployment_ledger: 0,
            }],
            asp_non_membership: NON_MEMBERSHIP.to_string(),
            verifiers: Default::default(),
            public_key_registry: String::new(),
            pools: vec![PoolConfigEntry {
                pool_contract_id: POOL.to_string(),
                token_contract_id: String::new(),
                deployment_ledger: 0,
                enabled: true,
                asset: AssetDescriptor::Native,
                policy_flags: PolicyFlags::default(),
                gvk_mode: GvkMode::Off,
                gvk_authority_pub_key: None,
            }],
        }
    }

    /// A client whose RPC refuses connections, so a test fails if it reaches
    /// the network.
    pub fn client() -> Client {
        static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "spp-operator-{}-{}.sqlite",
            std::process::id(),
            RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&db);
        let storage =
            crate::state::test_local_storage(db.to_string_lossy().as_ref()).expect("open storage");
        Client::init_readonly(
            "http://127.0.0.1:9",
            StorageHandle::from(storage),
            config(),
            None,
        )
        .expect("init client")
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::test_support::{ADDED_MEMBERSHIP, MEMBERSHIP, NON_MEMBERSHIP, POOL, client};
    use crate::Error;

    fn refusal(result: Result<impl Sized, Error>) -> String {
        match result {
            Err(Error::InvalidConfig(message)) => message,
            Err(other) => panic!("expected InvalidConfig, got {other}"),
            Ok(_) => panic!("expected a refusal"),
        }
    }

    #[test]
    fn ids_list_each_kind_of_administered_contract() {
        let client = client();
        assert_eq!(
            client.allowlist_ids(),
            vec![MEMBERSHIP.to_string(), ADDED_MEMBERSHIP.to_string()]
        );
        assert_eq!(client.blocklist_ids(), vec![NON_MEMBERSHIP.to_string()]);
        assert_eq!(client.pool_ids(), vec![POOL.to_string()]);
    }

    #[test]
    fn each_handle_opens_on_its_own_contract() {
        let client = client();
        for id in [MEMBERSHIP, ADDED_MEMBERSHIP] {
            let operator = client.allowlist_operator(id).expect("a membership tree");
            assert_eq!(operator.contract_id(), id);
        }
        let blocklist = client
            .blocklist_operator(NON_MEMBERSHIP)
            .expect("the non-membership tree");
        assert_eq!(blocklist.contract_id(), NON_MEMBERSHIP);
        let pool = client.pool_admin(POOL).expect("a pool");
        assert_eq!(pool.contract_id(), POOL);
    }

    #[test]
    fn each_handle_refuses_another_kind_of_contract() {
        let client = client();
        assert!(
            refusal(client.allowlist_operator(NON_MEMBERSHIP)).contains("not a membership tree")
        );
        assert!(
            refusal(client.blocklist_operator(MEMBERSHIP)).contains("not a non-membership tree")
        );
        assert!(refusal(client.pool_admin(MEMBERSHIP)).contains("not a pool"));
        assert!(refusal(client.allowlist_operator("unknown")).contains("not a membership tree"));
    }
}

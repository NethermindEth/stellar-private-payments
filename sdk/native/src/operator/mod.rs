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
//! [`crate::Client`], on any contract, listed in the config or not.

/// Defines a handle bound to one administered contract, with the methods every
/// such handle shares: opening, the admin read and the admin transfer.
/// `$ids` lists the deployment's contracts of the handle's kind.
macro_rules! contract_handle {
    ($(#[$doc:meta])* $handle:ident, $ids:ident) => {
        $(#[$doc])*
        pub struct $handle {
            rpc: crate::chain::RpcClient,
            contract_config: crate::types::ContractConfig,
            contract_id: String,
        }

        impl $handle {
            /// Opens a session over `rpc_url` for `contract_id`, listed in the
            /// deployment config or not; see [`Self::is_listed`].
            pub fn open(
                rpc_url: &str,
                contract_config: crate::types::ContractConfig,
                contract_id: &str,
            ) -> Result<Self, crate::Error> {
                Ok(Self::new(
                    crate::chain::RpcClient::new(rpc_url)?,
                    contract_config,
                    contract_id,
                ))
            }

            pub(crate) fn new(
                rpc: crate::chain::RpcClient,
                contract_config: crate::types::ContractConfig,
                contract_id: &str,
            ) -> Self {
                Self {
                    rpc,
                    contract_config,
                    contract_id: contract_id.to_string(),
                }
            }

            pub fn contract_id(&self) -> &str {
                &self.contract_id
            }

            /// Whether the deployment config lists the contract.
            pub fn is_listed(&self) -> bool {
                crate::operator::$ids(&self.contract_config).contains(&self.contract_id)
            }

            /// Admin and pending admin of the contract.
            pub async fn admin(&self) -> Result<crate::operator::AdminState, crate::Error> {
                crate::operator::read_admin(&self.rpc, &self.contract_config, &self.contract_id)
                    .await
            }

            /// Proposes `new_admin` (`G…` or `C…`) as the contract's admin,
            /// sourced by its current admin. The new admin takes over once it
            /// calls [`Self::accept_admin`]. Builders refuse calls for a
            /// contract admin, which has to authorize its own.
            pub async fn propose_admin(
                &self,
                new_admin: &str,
            ) -> Result<crate::operator::UnsignedOperatorCall, crate::Error> {
                let new_admin = crate::operator::address_arg(new_admin)?;
                self.admin_call("update_admin", vec![new_admin]).await
            }

            /// Withdraws the pending admin transfer, sourced by the current
            /// admin.
            pub async fn cancel_admin_transfer(
                &self,
            ) -> Result<crate::operator::UnsignedOperatorCall, crate::Error> {
                self.admin_call("cancel_admin_transfer", Vec::new()).await
            }

            /// Completes the pending admin transfer, sourced by the pending
            /// admin.
            pub async fn accept_admin(
                &self,
            ) -> Result<crate::operator::UnsignedOperatorCall, crate::Error> {
                crate::operator::accept_admin(&self.rpc, &self.contract_config, &self.contract_id)
                    .await
            }

            async fn admin_call(
                &self,
                method: &str,
                args: Vec<stellar_xdr::ScVal>,
            ) -> Result<crate::operator::UnsignedOperatorCall, crate::Error> {
                crate::operator::admin_call(
                    &self.rpc,
                    &self.contract_config,
                    &self.contract_id,
                    method,
                    args,
                )
                .await
            }
        }
    };
}

mod allowlist;
mod blocklist;
mod call;
mod envelope;
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
pub use call::{OperatorCall, UnsignedOperatorCall, describe};
pub use envelope::{CallStatus, Envelopes, SignerWeight, SigningStatus};
pub use gvk::GvkAuthority;
pub use pool_admin::{PoolAdmin, PoolLists};

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

/// Reads `get_admin` and `get_pending_admin` from `contract_id` by simulation.
async fn read_admin(
    rpc: &RpcClient,
    config: &ContractConfig,
    contract_id: &str,
) -> Result<AdminState, Error> {
    let source = &config.deployer;
    let (admin, pending) = futures::try_join!(
        rpc.read_contract(contract_id, source, "get_admin", Vec::new()),
        rpc.read_contract(contract_id, source, "get_pending_admin", Vec::new()),
    )?;
    Ok(AdminState {
        admin: scval_to_address_string(&admin)?,
        pending_admin: match pending {
            xdr::ScVal::Void => None,
            address => Some(scval_to_address_string(&address)?),
        },
    })
}

/// Builds the call of `method` on `contract_id`, sourced by its current admin.
async fn admin_call(
    rpc: &RpcClient,
    config: &ContractConfig,
    contract_id: &str,
    method: &str,
    args: Vec<xdr::ScVal>,
) -> Result<UnsignedOperatorCall, Error> {
    let admin = read_admin(rpc, config, contract_id).await?.admin;
    call::build_call(
        rpc,
        network_passphrase(config),
        &admin,
        contract_id,
        method,
        args,
    )
    .await
}

/// Parses a `G…` or `C…` strkey into an address argument.
fn address_arg(address: &str) -> Result<xdr::ScVal, Error> {
    let address: xdr::ScAddress = address
        .parse()
        .map_err(|_| Error::Refused(format!("{address} is not a Stellar address")))?;
    Ok(xdr::ScVal::Address(address))
}

/// Completes the admin transfer of `contract_id`, sourced by its pending
/// admin.
async fn accept_admin(
    rpc: &RpcClient,
    config: &ContractConfig,
    contract_id: &str,
) -> Result<UnsignedOperatorCall, Error> {
    let pending = read_admin(rpc, config, contract_id)
        .await?
        .pending_admin
        .ok_or_else(|| Error::Refused(format!("{contract_id} has no pending admin transfer")))?;
    call::build_call(
        rpc,
        network_passphrase(config),
        &pending,
        contract_id,
        "accept_admin",
        Vec::new(),
    )
    .await
}

fn network_passphrase(config: &ContractConfig) -> &str {
    config.network_passphrase.as_deref().unwrap_or_default()
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
            Err(Error::Refused(message)) => message,
            Err(other) => panic!("expected a refusal, got {other}"),
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
            let operator = client.allowlist_operator(id);
            assert_eq!(operator.contract_id(), id);
        }
        let blocklist = client.blocklist_operator(NON_MEMBERSHIP);
        assert_eq!(blocklist.contract_id(), NON_MEMBERSHIP);
        let pool = client.pool_admin(POOL);
        assert_eq!(pool.contract_id(), POOL);
    }

    #[tokio::test]
    async fn builders_refuse_an_address_argument_before_reading_the_chain() {
        let pool = client().pool_admin(POOL);
        assert!(
            refusal(pool.repoint_allowlist("not-an-address").await)
                .contains("not a Stellar address")
        );
        assert!(refusal(pool.propose_admin("").await).contains("not a Stellar address"));
    }

    #[test]
    fn handles_open_on_contracts_outside_the_config() {
        let client = client();
        let tree = client.allowlist_operator("new-tree");
        assert_eq!(tree.contract_id(), "new-tree");
        assert!(!tree.is_listed());
        assert!(!client.blocklist_operator("new-tree").is_listed());
        assert!(!client.pool_admin("new-pool").is_listed());

        assert!(client.allowlist_operator(ADDED_MEMBERSHIP).is_listed());
        assert!(client.blocklist_operator(NON_MEMBERSHIP).is_listed());
        assert!(client.pool_admin(POOL).is_listed());
        assert!(!client.pool_admin(NON_MEMBERSHIP).is_listed());
    }
}

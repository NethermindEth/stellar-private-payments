use std::collections::HashMap;

use anyhow::anyhow;
use stellar_xdr as xdr;

use crate::{
    Error,
    chain::{
        ContractDataBulkRequest, RpcClient, check_tree_code, scval_to_address_string,
        scval_to_policy_flags,
    },
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

/// The lists of each of `pools`, in order, read in one request.
pub async fn pool_lists(rpc_url: &str, pools: &[String]) -> Result<Vec<PoolLists>, Error> {
    read_lists(&RpcClient::new(rpc_url)?, pools).await
}

async fn read_lists(rpc: &RpcClient, pools: &[String]) -> Result<Vec<PoolLists>, Error> {
    let requests: Vec<_> = pools
        .iter()
        .map(|pool| ContractDataBulkRequest {
            contract_id: pool,
            enum_keys: Vec::new(),
        })
        .collect();
    let (state, _) = rpc.get_contract_data_bulk(&requests).await?;
    let empty = HashMap::new();
    pools
        .iter()
        .map(|pool| PoolLists::from_instance(pool, state.get(pool).unwrap_or(&empty)))
        .collect()
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
        read_lists(&self.rpc, std::slice::from_ref(&self.contract_id))
            .await?
            .pop()
            .ok_or_else(|| anyhow!("no lists read for pool {}", self.contract_id).into())
    }

    /// Points the pool at membership tree `tree`, sourced by the pool admin.
    /// The pool refuses a tree that does not run its allowlist code, and this
    /// refuses one that runs an executable reference, which the pool accepts.
    pub async fn repoint_allowlist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        let arg = address_arg(tree)?;
        self.check_tree_code(tree, "ASPMembershipWasmHash").await?;
        self.admin_call("update_asp_membership", vec![arg]).await
    }

    /// Points the pool at non-membership tree `tree`, sourced by the pool
    /// admin. The pool refuses a tree that does not run its blocklist code,
    /// and this refuses one that runs an executable reference.
    pub async fn repoint_blocklist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        let arg = address_arg(tree)?;
        self.check_tree_code(tree, "ASPNonMembershipWasmHash")
            .await?;
        self.admin_call("update_asp_non_membership", vec![arg])
            .await
    }

    async fn check_tree_code(&self, tree: &str, hash_key: &str) -> Result<(), Error> {
        let requests =
            [self.contract_id.as_str(), tree].map(|contract_id| ContractDataBulkRequest {
                contract_id,
                enum_keys: Vec::new(),
            });
        let (state, _) = self.rpc.get_contract_data_bulk(&requests).await?;
        let empty = HashMap::new();
        let pool_state = state.get(&self.contract_id).unwrap_or(&empty);
        check_tree_code(
            &self.contract_id,
            pool_state,
            tree,
            state.get(tree),
            hash_key,
        )?;
        Ok(())
    }

    /// Stops deposits; transfers and withdrawals continue.
    pub async fn pause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("pause_deposits", Vec::new()).await
    }

    pub async fn unpause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        self.admin_call("unpause_deposits", Vec::new()).await
    }

    /// Pays `amount` of the collected fees, in the token's base units, to
    /// `to`, sourced by the pool admin. The pool refuses an amount above the
    /// fees collected and a `to` that is the pool or its token.
    pub async fn claim_fees(&self, to: &str, amount: i128) -> Result<UnsignedOperatorCall, Error> {
        let to = address_arg(to)?;
        if amount < 0 {
            return Err(Error::Refused(format!("claim amount {amount} is negative")));
        }
        let bytes = amount.to_be_bytes();
        let (hi, lo) = bytes.split_at(8);
        let amount = xdr::ScVal::I128(xdr::Int128Parts {
            hi: i64::from_be_bytes(hi.try_into().expect("8 bytes")),
            lo: u64::from_be_bytes(lo.try_into().expect("8 bytes")),
        });
        self.admin_call("claim_fees", vec![to, amount]).await
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

// The mocked RPC is native-only.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod rpc_tests {
    use serde_json::{Value, json};
    use stellar_xdr::{Limits, WriteXdr};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::method};

    use super::*;
    use crate::types::ContractConfig;

    fn contract(byte: u8) -> String {
        stellar_strkey::Contract([byte; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    /// The instance entry of contract `byte`, as `getLedgerEntries` returns it.
    fn instance_entry(
        byte: u8,
        executable: xdr::ContractExecutable,
        storage: Vec<(&str, xdr::ScVal)>,
    ) -> Value {
        let contract = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([byte; 32])));
        let storage: Vec<_> = storage
            .into_iter()
            .map(|(name, val)| {
                let name = xdr::ScVal::Symbol(name.try_into().expect("symbol"));
                xdr::ScMapEntry {
                    key: xdr::ScVal::Vec(Some(vec![name].try_into().expect("key"))),
                    val,
                }
            })
            .collect();
        let key = xdr::ScVal::LedgerKeyContractInstance;
        let durability = xdr::ContractDataDurability::Persistent;
        let ledger_key = xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: contract.clone(),
            key: key.clone(),
            durability,
        });
        let entry = xdr::LedgerEntryData::ContractData(xdr::ContractDataEntry {
            ext: xdr::ExtensionPoint::V0,
            contract,
            key,
            durability,
            val: xdr::ScVal::ContractInstance(xdr::ScContractInstance {
                executable,
                storage: Some(storage.try_into().expect("storage")),
            }),
        });
        json!({
            "key": ledger_key.to_xdr_base64(Limits::none()).expect("key XDR"),
            "xdr": entry.to_xdr_base64(Limits::none()).expect("entry XDR"),
            "lastModifiedLedgerSeq": 1,
        })
    }

    /// The admin of a pool, contract 1, that stores `[7; 32]` as both trees'
    /// code, and a tree, contract 2, that runs `tree_code`.
    async fn admin_with_tree(tree_code: xdr::ContractExecutable) -> (MockServer, PoolAdmin) {
        let pinned = xdr::ScVal::Bytes(vec![7; 32].try_into().expect("hash"));
        let pool_code = xdr::ContractExecutable::Wasm(xdr::Hash([0; 32]));
        let entries = vec![
            instance_entry(
                1,
                pool_code,
                vec![
                    ("ASPMembershipWasmHash", pinned.clone()),
                    ("ASPNonMembershipWasmHash", pinned),
                ],
            ),
            instance_entry(2, tree_code, Vec::new()),
        ];
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(move |request: &Request| {
                let body: Value = request.body_json().expect("JSON-RPC request");
                assert_eq!(body["method"], "getLedgerEntries");
                let keys = body["params"]["keys"].as_array().expect("requested keys");
                let requested: Vec<_> = entries
                    .iter()
                    .filter(|entry| keys.contains(&entry["key"]))
                    .collect();
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "latestLedger": 42, "entries": requested },
                }))
            })
            .mount(&server)
            .await;
        let rpc = RpcClient::new(&server.uri()).expect("RPC");
        let admin = PoolAdmin::new(rpc, ContractConfig::default(), &contract(1));
        (server, admin)
    }

    #[tokio::test]
    async fn repointing_refuses_a_tree_running_an_executable_reference() {
        let reference = xdr::ContractExecutable::ExternalRef(xdr::ContractExecutableExternalRef {
            executable_owner: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32]))),
            tag: b"tree".to_vec().try_into().expect("tag"),
        });
        let (_server, admin) = admin_with_tree(reference).await;
        for result in [
            admin.repoint_allowlist(&contract(2)).await,
            admin.repoint_blocklist(&contract(2)).await,
        ] {
            let err = result.expect_err("reference tree");
            assert!(err.to_string().contains("executable reference"), "{err}");
        }
    }

    #[tokio::test]
    async fn repointing_refuses_a_tree_running_other_wasm() {
        let other = xdr::ContractExecutable::Wasm(xdr::Hash([8; 32]));
        let (_server, admin) = admin_with_tree(other).await;
        for result in [
            admin.repoint_allowlist(&contract(2)).await,
            admin.repoint_blocklist(&contract(2)).await,
        ] {
            let err = result.expect_err("other code");
            assert!(err.to_string().contains("runs other code"), "{err}");
        }
    }

    #[tokio::test]
    async fn a_tree_running_the_pinned_wasm_passes_the_repoint_check() {
        let pinned = xdr::ContractExecutable::Wasm(xdr::Hash([7; 32]));
        let (_server, admin) = admin_with_tree(pinned).await;
        for hash_key in ["ASPMembershipWasmHash", "ASPNonMembershipWasmHash"] {
            admin
                .check_tree_code(&contract(2), hash_key)
                .await
                .expect("pinned code");
        }
    }
}

//! A pool deployed in the test host, and its ledger entries as an RPC reports
//! them.
//!
//! Tests that read a pool through the SDK serve these entries back verbatim, so
//! nothing outside the contracts describes their storage layout.

use super::utils::{test_env, wasm_hash};
use asp_membership::ASPMembership;
use asp_non_membership::ASPNonMembership;
use pool::PoolContract;
use pool_core::policy;
use soroban_sdk::{Address, Env, U256, testutils::Address as _};
use stellar_private_payments::types::{
    AssetDescriptor, ContractConfig, GvkMode, PolicyFlags, PoolConfigEntry,
};
use stellar_xdr::{Limits, WriteXdr};

/// A contract address as the strkey the SDK reports.
pub fn strkey(address: &Address) -> String {
    let text = address.to_string();
    let mut buf = std::vec![0u8; text.len() as usize];
    text.copy_into_slice(&mut buf);
    String::from_utf8(buf).expect("a strkey is ASCII")
}

/// Tree depth the deployment scripts pass.
pub const LEVELS: u32 = 20;

/// Membership tree depth the deployment scripts pass.
pub const MEMBERSHIP_LEVELS: u32 = 10;

/// Deposit cap the fixture registers the pool with.
pub const MAXIMUM_DEPOSIT: u32 = 1_000_000;

pub struct Deployment {
    pub env: Env,
    pub pool: Address,
    pub admin: Address,
    pub token: Address,
    pub verifier: Address,
    pub asp_membership: Address,
    pub asp_non_membership: Address,
}

/// Registers a pool and the two association sets it names.
///
/// The association sets are registered for real, because the reader fetches
/// their entries too. The token and the verifier stay placeholder addresses:
/// the pool only stores their addresses and the reader only reports them.
pub fn deploy() -> Deployment {
    let env = test_env();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let verifier = Address::generate(&env);
    let asp_membership = env.register(ASPMembership, (admin.clone(), MEMBERSHIP_LEVELS));
    let asp_non_membership = env.register(ASPNonMembership, (admin.clone(),));
    let pool = env.register(
        PoolContract,
        (
            admin.clone(),
            token.clone(),
            verifier.clone(),
            asp_membership.clone(),
            asp_non_membership.clone(),
            wasm_hash(&asp_membership),
            wasm_hash(&asp_non_membership),
            U256::from_u32(&env, MAXIMUM_DEPOSIT),
            LEVELS,
            policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
            soroban_sdk::String::from_str(&env, "tests"),
        ),
    );
    Deployment {
        env,
        pool,
        admin,
        token,
        verifier,
        asp_membership,
        asp_non_membership,
    }
}

/// Every contract-data entry the host holds, as an RPC would report it.
///
/// The entries come from the host's ledger snapshot, so they are the bytes the
/// contracts wrote rather than a description of them.
pub fn ledger_entries_as_rpc_results(env: &Env) -> Vec<serde_json::Value> {
    env.to_ledger_snapshot()
        .ledger_entries
        .iter()
        .filter_map(|(key, (entry, _ttl))| {
            let stellar_xdr::LedgerKey::ContractData(_) = key.as_ref() else {
                return None;
            };
            Some(serde_json::json!({
                "key": key.to_xdr_base64(Limits::none()).expect("key xdr"),
                "xdr": entry.data.to_xdr_base64(Limits::none()).expect("entry xdr"),
                "lastModifiedLedgerSeq": 1,
            }))
        })
        .collect()
}

pub fn config_for(deployment: &Deployment, uri: &str) -> (ContractConfig, PoolConfigEntry) {
    let pool = PoolConfigEntry {
        pool_contract_id: strkey(&deployment.pool),
        token_contract_id: strkey(&deployment.token),
        deployment_ledger: 1,
        enabled: true,
        asset: AssetDescriptor::Native,
        policy_flags: PolicyFlags::from_bits(policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT)
            .expect("the fixture's policy flags"),
        gvk_mode: GvkMode::Off,
        gvk_authority_pub_key: None,
    };
    let config = ContractConfig {
        network_passphrase: None,
        rpc_url: None,
        network: uri.to_string(),
        kdf_domain: "tests".to_string(),
        deployer: strkey(&deployment.admin),
        admin: strkey(&deployment.admin),
        asp_membership: strkey(&deployment.asp_membership),
        added_asp_memberships: Vec::new(),
        asp_non_membership: strkey(&deployment.asp_non_membership),
        verifiers: [("AB".to_string(), strkey(&deployment.verifier))]
            .into_iter()
            .collect(),
        public_key_registry: strkey(&Address::generate(&deployment.env)),
        pools: vec![pool.clone()],
    };
    (config, pool)
}

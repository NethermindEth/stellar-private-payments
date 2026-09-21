//! The SDK's contract reader against a pool's own ledger entries.
//!
//! [`StateFetcher::contracts_data_for_pool`] turns the entries an RPC returns
//! into a [`PoolInfo`]. Its unit tests build those entries by hand, so a change
//! to what a contract writes cannot fail them: the pool moved its configuration
//! into the instance entry and its tree into one packed entry, and the reader
//! went on parsing hand-written entries in the old shape while a freshly
//! deployed pool could not be read at all.
//!
//! These tests close that loop. A pool is deployed in the test host, its real
//! ledger entries are taken from the host's own snapshot, and an RPC serves
//! them back verbatim. Nothing here describes the storage layout, so the layout
//! can only be described in one place: the contracts.

use super::utils::test_env;
use anyhow::Result;
use asp_membership::ASPMembership;
use asp_non_membership::ASPNonMembership;
use pool::PoolContract;
use pool_core::policy;
use soroban_sdk::{Address, Env, U256, testutils::Address as _};
use stellar_private_payments::{
    chain::{Client, StateFetcher},
    types::{AssetDescriptor, ContractConfig, ExtAmount, GvkMode, PolicyFlags, PoolConfigEntry},
};
use stellar_xdr::{Limits, WriteXdr};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// A contract address as the strkey the SDK reports.
fn strkey(address: &Address) -> String {
    let text = address.to_string();
    let mut buf = std::vec![0u8; text.len() as usize];
    text.copy_into_slice(&mut buf);
    String::from_utf8(buf).expect("a strkey is ASCII")
}

/// Tree depth the deployment scripts pass.
const LEVELS: u32 = 20;

/// Membership tree depth the deployment scripts pass.
const MEMBERSHIP_LEVELS: u32 = 10;

/// Deposit cap the fixture registers the pool with.
const MAXIMUM_DEPOSIT: u32 = 1_000_000;

struct Deployment {
    env: Env,
    pool: Address,
    admin: Address,
    token: Address,
    verifier: Address,
    asp_membership: Address,
    asp_non_membership: Address,
}

/// Registers a pool and the two association sets it names.
///
/// The association sets are registered for real, because the reader fetches
/// their entries too. The token and the verifier stay placeholder addresses:
/// the pool only stores their addresses and the reader only reports them.
fn deploy() -> Deployment {
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
            U256::from_u32(&env, MAXIMUM_DEPOSIT),
            LEVELS,
            policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
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
fn ledger_entries_as_rpc_results(env: &Env) -> Vec<serde_json::Value> {
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

/// An RPC that answers every `getLedgerEntries` with the same entries.
///
/// The reader asks for the keys it wants and takes what comes back, so serving
/// the whole set exercises the same selection it performs against a real node.
async fn rpc_serving(entries: Vec<serde_json::Value>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "entries": entries, "latestLedger": 1 },
        })))
        .mount(&server)
        .await;
    server
}

fn config_for(deployment: &Deployment, uri: &str) -> (ContractConfig, PoolConfigEntry) {
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
        network: uri.to_string(),
        deployer: strkey(&deployment.admin),
        admin: strkey(&deployment.admin),
        asp_membership: strkey(&deployment.asp_membership),
        asp_non_membership: strkey(&deployment.asp_non_membership),
        verifiers: [("AB".to_string(), strkey(&deployment.verifier))]
            .into_iter()
            .collect(),
        public_key_registry: strkey(&Address::generate(&deployment.env)),
        pools: vec![pool.clone()],
    };
    (config, pool)
}

/// A freshly deployed pool must be readable, with the values it was deployed
/// with.
#[tokio::test]
async fn the_reader_parses_a_deployed_pools_own_entries() -> Result<()> {
    let deployment = deploy();
    let server = rpc_serving(ledger_entries_as_rpc_results(&deployment.env)).await;
    let (config, pool) = config_for(&deployment, &server.uri());
    let fetcher = StateFetcher::new(Client::new(&server.uri())?, config)?;

    let data = fetcher
        .contracts_data_for_pool(&pool.pool_contract_id)
        .await?;
    let info = data
        .pools
        .first()
        .unwrap_or_else(|| panic!("expected the pool to be reported"));

    assert_eq!(info.contract_id, strkey(&deployment.pool));
    assert_eq!(info.admin, strkey(&deployment.admin));
    assert_eq!(info.token, strkey(&deployment.token));
    assert_eq!(info.verifier, strkey(&deployment.verifier));
    assert_eq!(info.asp_membership, strkey(&deployment.asp_membership));
    assert_eq!(
        info.asp_non_membership,
        strkey(&deployment.asp_non_membership)
    );
    assert_eq!(info.merkle_levels, LEVELS);
    assert_eq!(info.merkle_capacity, 1u64 << LEVELS);
    assert_eq!(info.merkle_next_index, "0");
    assert_eq!(
        info.maximum_deposit_amount,
        ExtAmount::from(i128::from(MAXIMUM_DEPOSIT))
    );
    Ok(())
}

/// The root the reader derives from the packed tree entry must be the root the
/// contract itself reports.
///
/// The ring slot is no longer stored, so the reader recomputes it from the leaf
/// counter. A slot that disagreed with the contract's would hand a caller a
/// stale root that still verifies as known.
#[tokio::test]
async fn the_reader_derives_the_root_the_contract_reports() -> Result<()> {
    let deployment = deploy();
    let contract_root = pool::PoolContractClient::new(&deployment.env, &deployment.pool).get_root();

    let server = rpc_serving(ledger_entries_as_rpc_results(&deployment.env)).await;
    let (config, pool) = config_for(&deployment, &server.uri());
    let fetcher = StateFetcher::new(Client::new(&server.uri())?, config)?;

    let data = fetcher
        .contracts_data_for_pool(&pool.pool_contract_id)
        .await?;
    let info = data
        .pools
        .first()
        .unwrap_or_else(|| panic!("expected the pool to be reported"));
    let root = info
        .merkle_root
        .unwrap_or_else(|| panic!("expected a root to be reported"));

    let mut expected = [0u8; 32];
    contract_root.to_be_bytes().copy_into_slice(&mut expected);
    assert_eq!(root.to_be_bytes(), expected);
    Ok(())
}

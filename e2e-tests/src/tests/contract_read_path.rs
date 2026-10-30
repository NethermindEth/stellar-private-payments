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

use super::deployment::{
    LEVELS, MAXIMUM_DEPOSIT, config_for, deploy, ledger_entries_as_rpc_results, strkey,
};
use anyhow::Result;
use stellar_private_payments::{
    chain::{Client, StateFetcher},
    types::ExtAmount,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

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

/// A pool whose admin paused deposits must read as paused.
#[tokio::test]
async fn the_reader_sees_a_paused_pool() -> Result<()> {
    let deployment = deploy();
    pool::PoolContractClient::new(&deployment.env, &deployment.pool).pause_deposits();

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

    assert!(info.deposits_paused);
    Ok(())
}

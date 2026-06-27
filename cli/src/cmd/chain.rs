use anyhow::Result;
use serde::Serialize;
use stellar_private_payments_sdk::{Client, blocking::block_on, types::PoolConfigEntry};

use crate::{config::CliConfig, output};

#[derive(Serialize)]
struct PoolSummary {
    pool_contract_id: String,
    token_contract_id: String,
    deployment_ledger: u32,
    enabled: bool,
    asset: String,
}

pub fn pools(config: &CliConfig, json: bool) -> Result<()> {
    let pools: Vec<PoolSummary> = config.deployment.pools.iter().map(pool_summary).collect();

    if json {
        output::emit(&pools, true)?;
        return Ok(());
    }

    output::print_section("Deployment pools");
    if pools.is_empty() {
        println!("(none)");
        return Ok(());
    }

    for pool in &pools {
        output::print_kv("pool", &pool.pool_contract_id);
        output::print_kv("  token", &pool.token_contract_id);
        output::print_kv("  asset", &pool.asset);
        output::print_kv("  deployment_ledger", pool.deployment_ledger);
        output::print_kv("  enabled", pool.enabled);
        println!();
    }
    Ok(())
}

pub fn status(config: &CliConfig, json: bool) -> Result<()> {
    let client = Client::new(&config.rpc_url, config.deployment.clone())?;
    let state = block_on(client.all_contracts_data())?;

    if json {
        output::emit(&state, true)?;
        return Ok(());
    }

    output::print_section("On-chain status");
    output::print_kv("pools", state.pools.len());
    for pool in &state.pools {
        output::print_kv("pool", &pool.contract_id);
        if let Some(root) = &pool.merkle_root {
            output::print_kv("  merkle_root", root.to_string());
        }
        output::print_kv("  merkle_next_index", &pool.merkle_next_index);
        output::print_kv("  merkle_levels", pool.merkle_levels);
    }
    Ok(())
}

pub fn asp(config: &CliConfig, json: bool) -> Result<()> {
    let client = Client::new(&config.rpc_url, config.deployment.clone())?;
    let state = block_on(client.asp_state())?;

    if json {
        output::emit(&state, true)?;
        return Ok(());
    }

    output::print_section("ASP state");
    output::print_kv("membership_contract", &state.asp_membership.contract_id);
    output::print_kv("  membership_root", state.asp_membership.root.to_string());
    output::print_kv(
        "non_membership_contract",
        &state.asp_non_membership.contract_id,
    );
    output::print_kv(
        "  non_membership_root",
        state.asp_non_membership.root.to_string(),
    );
    Ok(())
}

fn pool_summary(entry: &PoolConfigEntry) -> PoolSummary {
    PoolSummary {
        pool_contract_id: entry.pool_contract_id.clone(),
        token_contract_id: entry.token_contract_id.clone(),
        deployment_ledger: entry.deployment_ledger,
        enabled: entry.enabled,
        asset: format!("{:?}", entry.asset),
    }
}

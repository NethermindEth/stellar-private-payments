//! `overview` — dashboard-style view of pools, balances, contracts, network,
//! and this account's registration status.

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments_sdk::types::AssetDescriptor;

use crate::{config::CliConfig, explorer::Explorer, onboard, output, session::PoolSession};

#[derive(Serialize)]
struct ContractRef {
    contract_id: String,
    link: String,
}

#[derive(Serialize)]
struct PoolRow {
    pool_contract_id: String,
    pool_link: String,
    token_contract_id: String,
    token_link: String,
    asset: String,
    balance_stroops: String,
}

#[derive(Serialize)]
struct Overview {
    network: String,
    rpc_url: String,
    account: String,
    account_link: String,
    registered: bool,
    pools: Vec<PoolRow>,
    asp_membership: ContractRef,
    asp_non_membership: ContractRef,
    public_key_registry: ContractRef,
}

pub fn run(config: &CliConfig, json: bool) -> Result<()> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let explorer = Explorer::new(explorer_base(config)?);

    let mut pools = Vec::new();
    for entry in config.deployment.pools.iter().filter(|p| p.enabled) {
        let session = PoolSession::open(
            config,
            &account,
            &network,
            &entry.pool_contract_id,
            config.circuits_dir.as_deref(),
        )?;
        let balance = session
            .pool()
            .balance()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        pools.push(PoolRow {
            pool_contract_id: entry.pool_contract_id.clone(),
            pool_link: explorer.contract(&entry.pool_contract_id),
            token_contract_id: entry.token_contract_id.clone(),
            token_link: explorer.contract(&entry.token_contract_id),
            asset: asset_label(&entry.asset),
            balance_stroops: balance.to_string(),
        });
    }

    // Pools were just synced, so the local registry index is current.
    let storage = config.open_storage()?;
    let registered = storage
        .lookup_public_key_by_address(&account.address)?
        .is_some();

    let dep = &config.deployment;
    let overview = Overview {
        network: config.network.clone(),
        rpc_url: network.rpc_url.clone(),
        account: account.address.clone(),
        account_link: explorer.account(&account.address),
        registered,
        pools,
        asp_membership: contract_ref(&explorer, &dep.asp_membership),
        asp_non_membership: contract_ref(&explorer, &dep.asp_non_membership),
        public_key_registry: contract_ref(&explorer, &dep.public_key_registry),
    };

    if json {
        return output::emit(&overview, true);
    }
    print_human(&overview, &account.alias);
    Ok(())
}

fn print_human(o: &Overview, alias: &str) {
    output::print_section("Network");
    output::print_kv("network", &o.network);
    output::print_kv("rpc_url", &o.rpc_url);
    output::print_kv("account", format!("{} → {}", o.account, o.account_link));
    if o.registered {
        output::print_kv("registration", "registered");
    } else {
        output::print_kv(
            "registration",
            format!("not registered (run: spp register --source-account {alias})"),
        );
    }

    println!();
    output::print_section("Pools");
    if o.pools.is_empty() {
        println!("(none)");
    }
    for pool in &o.pools {
        output::print_kv("pool", format!("{} → {}", pool.pool_contract_id, pool.pool_link));
        output::print_kv(
            "  token",
            format!("{} → {}", pool.token_contract_id, pool.token_link),
        );
        output::print_kv("  asset", &pool.asset);
        output::print_kv("  balance_stroops", &pool.balance_stroops);
        println!();
    }

    output::print_section("Contracts");
    print_ref("asp_membership", &o.asp_membership);
    print_ref("asp_non_membership", &o.asp_non_membership);
    print_ref("public_key_registry", &o.public_key_registry);
}

fn print_ref(label: &str, r: &ContractRef) {
    output::print_kv(label, format!("{} → {}", r.contract_id, r.link));
}

fn contract_ref(explorer: &Explorer, contract_id: &str) -> ContractRef {
    ContractRef {
        contract_id: contract_id.to_string(),
        link: explorer.contract(contract_id),
    }
}

fn explorer_base(config: &CliConfig) -> Result<String> {
    let storage = config.open_storage()?;
    crate::explorer::base_url(&storage)
}

fn asset_label(asset: &AssetDescriptor) -> String {
    match asset {
        AssetDescriptor::Native => "native (XLM)".to_string(),
        AssetDescriptor::Classic { code, .. } => format!("{code} (classic)"),
        AssetDescriptor::Contract { symbol, .. } => format!("{symbol} (contract)"),
    }
}

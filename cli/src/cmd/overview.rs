//! `overview` — dashboard-style view of pools, balances, contracts, network,
//! and this account's registration status.

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments_sdk::types::AssetDescriptor;

use crate::{
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::PoolSession,
};

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
    balance: String,
}

#[derive(Serialize)]
struct PoolErrorRow {
    pool_contract_id: String,
    error: String,
}

#[derive(Serialize)]
struct Overview {
    network: String,
    rpc_url: String,
    account: String,
    account_link: String,
    registered: bool,
    pools: Vec<PoolRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<PoolErrorRow>,
    asp_membership: ContractRef,
    asp_non_membership: ContractRef,
    public_key_registry: ContractRef,
}

pub fn run(config: &CliConfig, pool: Option<&str>, json: bool) -> Result<()> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let explorer = Explorer::new(explorer_base(config)?);

    let entries: Vec<_> = match pool {
        Some(pool) => {
            validate_pool(pool, &config.deployment)?;
            config
                .deployment
                .pools
                .iter()
                .filter(|entry| entry.enabled && entry.pool_contract_id == pool)
                .collect()
        }
        None => config
            .deployment
            .pools
            .iter()
            .filter(|p| p.enabled)
            .collect(),
    };

    let mut pools = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        // A read-only session: no prover is built, so we skip the ~8MB proving
        // key deserialization + circuit-WASM compile that a transact open pays.
        let row = (|| -> Result<PoolRow> {
            let session =
                PoolSession::open_readonly(config, &account, &network, &entry.pool_contract_id)?;
            let balance = session
                .pool()
                .balance()
                .map_err(|e| anyhow::anyhow!("balance: {e}"))?;
            Ok(PoolRow {
                pool_contract_id: entry.pool_contract_id.clone(),
                pool_link: explorer.contract(&entry.pool_contract_id),
                token_contract_id: entry.token_contract_id.clone(),
                token_link: explorer.contract(&entry.token_contract_id),
                asset: asset_label(&entry.asset),
                balance: output::format_token_amount(
                    u128::from(balance),
                    &asset_symbol(&entry.asset),
                    7,
                ),
            })
        })();
        match row {
            Ok(row) => pools.push(row),
            // One unreachable/misconfigured pool should not blank the whole
            // dashboard: report it and keep rendering the rest.
            Err(e) => {
                log::warn!("pool {}: {e:#}", entry.pool_contract_id);
                errors.push(PoolErrorRow {
                    pool_contract_id: entry.pool_contract_id.clone(),
                    error: format!("{e:#}"),
                });
            }
        }
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
        errors,
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
    output::print_section(if o.pools.len() == 1 { "Pool" } else { "Pools" });
    if o.pools.is_empty() {
        println!("(none)");
    }
    for pool in &o.pools {
        output::print_kv(
            "pool",
            format!("{} → {}", pool.pool_contract_id, pool.pool_link),
        );
        output::print_kv(
            "  token",
            format!("{} → {}", pool.token_contract_id, pool.token_link),
        );
        output::print_kv("  asset", &pool.asset);
        output::print_kv("  balance", &pool.balance);
        println!();
    }

    if !o.errors.is_empty() {
        output::print_section("Unavailable pools");
        for err in &o.errors {
            output::print_kv(&err.pool_contract_id, &err.error);
        }
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

fn asset_symbol(asset: &AssetDescriptor) -> String {
    match asset {
        AssetDescriptor::Native => "XLM".to_string(),
        AssetDescriptor::Classic { code, .. } => {
            if code.is_empty() {
                "Asset".to_string()
            } else {
                code.clone()
            }
        }
        AssetDescriptor::Contract { symbol, .. } => {
            if symbol.is_empty() {
                "Token".to_string()
            } else {
                symbol.clone()
            }
        }
    }
}

fn asset_label(asset: &AssetDescriptor) -> String {
    match asset {
        AssetDescriptor::Native => "native (XLM)".to_string(),
        AssetDescriptor::Classic { code, .. } => format!("{code} (classic)"),
        AssetDescriptor::Contract { symbol, .. } => format!("{symbol} (contract)"),
    }
}

//! `overview` — dashboard-style view of pools, balances, fees and limits,
//! contracts, network, and this account's registration status.

use std::collections::HashSet;

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments::types::{AssetDescriptor, NoteAmount, PoolInfo};

use crate::{
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::ClientSession,
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
    balance_base_units: String,
    decimals: Option<u32>,
    #[serde(flatten)]
    limits: Option<PoolLimits>,
}

/// A pool's fee and smallest deposit, and the most one spend from this
/// account's notes can send after fees, in the token's units and in base units.
#[derive(Serialize)]
struct PoolLimits {
    pool_fee: String,
    pool_fee_base_units: NoteAmount,
    smallest_deposit: String,
    smallest_deposit_base_units: NoteAmount,
    max_to_send: String,
    max_to_send_base_units: NoteAmount,
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

#[tracing::instrument(
    name = "cmd_overview",
    skip_all,
    fields(correlation_id = %stellar_private_payments::types::correlation_id_or_new())
)]
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

    let session = ClientSession::new(config, &account, &network, true)?;
    let allowed: HashSet<_> = entries
        .iter()
        .map(|entry| entry.pool_contract_id.as_str())
        .collect();

    let mut pools = Vec::new();
    let mut errors = Vec::new();

    match session.account().portfolio() {
        Ok(portfolio) => {
            let ids: Vec<_> = portfolio
                .iter()
                .map(|balance| balance.pool_contract_id.as_str())
                .filter(|id| allowed.contains(id))
                .collect();
            let precision = session.token_decimals(ids.iter().copied());
            let limits = session.pool_limits(ids);
            (pools, errors) = portfolio_rows(&portfolio, &entries, &explorer, &precision, &limits);
        }
        Err(e) => {
            log::warn!("portfolio: {e:#}");
            for entry in entries {
                errors.push(PoolErrorRow {
                    pool_contract_id: entry.pool_contract_id.clone(),
                    error: format!("{e:#}"),
                });
            }
        }
    }

    let registered = session.account().is_registered().unwrap_or(false);

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
        output::print_kv("registration", "address is publicly registered");
    } else {
        output::print_kv(
            "registration",
            format!("address is not publicly registered (run: spp register --account {alias})"),
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
        if let Some(limits) = &pool.limits {
            output::print_kv("  pool_fee", &limits.pool_fee);
            output::print_kv("  smallest_deposit", &limits.smallest_deposit);
            output::print_kv("  max_to_send", &limits.max_to_send);
        }
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
    crate::explorer::base_url(&storage, &config.deployment)
}

pub fn asset_symbol(asset: &AssetDescriptor) -> String {
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
        AssetDescriptor::Native => "XLM (native)".to_string(),
        AssetDescriptor::Classic { code, .. } => format!("{code} (classic)"),
        AssetDescriptor::Contract { symbol, .. } => format!("{symbol} (contract)"),
    }
}

fn portfolio_rows(
    portfolio: &[stellar_private_payments::types::PortfolioBalance],
    entries: &[&stellar_private_payments::types::PoolConfigEntry],
    explorer: &Explorer,
    precision: &std::collections::HashMap<String, Result<u32>>,
    limits: &std::collections::HashMap<String, Result<(PoolInfo, NoteAmount)>>,
) -> (Vec<PoolRow>, Vec<PoolErrorRow>) {
    let mut pools = Vec::new();
    let mut errors = Vec::new();
    for balance in portfolio {
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.pool_contract_id == balance.pool_contract_id)
        else {
            continue;
        };
        let decimals = match precision.get(&entry.pool_contract_id) {
            Some(Ok(decimals)) => Some(*decimals),
            Some(Err(error)) => {
                errors.push(PoolErrorRow {
                    pool_contract_id: entry.pool_contract_id.clone(),
                    error: error.to_string(),
                });
                None
            }
            None => None,
        };
        let symbol = asset_symbol(&entry.asset);
        let amount = |base_units: NoteAmount| {
            output::format_token_amount(u128::from(base_units), &symbol, decimals)
        };
        let limits = match limits.get(&entry.pool_contract_id) {
            Some(Ok((info, max_to_send))) => Some(PoolLimits {
                pool_fee: amount(info.fee),
                pool_fee_base_units: info.fee,
                smallest_deposit: amount(info.minimum_deposit_amount),
                smallest_deposit_base_units: info.minimum_deposit_amount,
                max_to_send: amount(*max_to_send),
                max_to_send_base_units: *max_to_send,
            }),
            Some(Err(error)) => {
                errors.push(PoolErrorRow {
                    pool_contract_id: entry.pool_contract_id.clone(),
                    error: format!(
                        "pool fee, smallest deposit and max to send unavailable: {error}"
                    ),
                });
                None
            }
            None => None,
        };
        pools.push(PoolRow {
            pool_contract_id: balance.pool_contract_id.clone(),
            pool_link: explorer.contract(&balance.pool_contract_id),
            token_contract_id: entry.token_contract_id.clone(),
            token_link: explorer.contract(&entry.token_contract_id),
            asset: asset_label(&entry.asset),
            balance_base_units: balance.amount.to_string(),
            decimals,
            balance: amount(balance.amount),
            limits,
        });
    }
    for entry in entries {
        if portfolio
            .iter()
            .any(|balance| balance.pool_contract_id == entry.pool_contract_id)
        {
            continue;
        }
        errors.push(PoolErrorRow {
            pool_contract_id: entry.pool_contract_id.clone(),
            error: "pool balance unavailable".into(),
        });
    }
    (pools, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_private_payments::types::{ExtAmount, PolicyFlags, PortfolioBalance};

    fn entry() -> stellar_private_payments::types::PoolConfigEntry {
        serde_json::from_value(serde_json::json!({
            "poolContractId": "pool", "tokenContractId": "token", "enabled": true,
            "deploymentLedger": 0, "policyFlags": [], "asset": {"kind": "native"}
        }))
        .expect("pool")
    }

    fn balances() -> [PortfolioBalance; 1] {
        [PortfolioBalance {
            pool_contract_id: "pool".into(),
            token_contract_id: "token".into(),
            token_label: "XLM".into(),
            amount: NoteAmount::from(123u128),
            note_count: 1,
        }]
    }

    /// A pool charging a fee of 1000 with a smallest deposit of 10000.
    fn pool_info() -> PoolInfo {
        PoolInfo {
            ledger: 0,
            contract_id: "pool".into(),
            contract_type: String::new(),
            admin: String::new(),
            token: "token".into(),
            verifier: String::new(),
            asp_membership: String::new(),
            asp_non_membership: String::new(),
            merkle_levels: 0,
            merkle_current_root_index: None,
            merkle_next_index: "0".into(),
            maximum_deposit_amount: ExtAmount::from(1_000_000_000i128),
            deposits_paused: false,
            fee: NoteAmount::from(1_000u128),
            minimum_deposit_amount: NoteAmount::from(10_000u128),
            merkle_root: None,
            merkle_capacity: 0,
            total_commitments: "0".into(),
            policy_flags: PolicyFlags::EMPTY,
            admin_view_key: None,
            gvk_mode: None,
        }
    }

    #[test]
    fn metadata_failure_keeps_balance_and_reports_pool_error() {
        let (rows, errors) = portfolio_rows(
            &balances(),
            &[&entry()],
            &Explorer::new("https://example.test"),
            &[("pool".into(), Err(anyhow::anyhow!("offline")))].into(),
            &Default::default(),
        );
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).expect("JSON");
        assert_eq!(row["balance"], "123 base units");
        assert_eq!(row["balance_base_units"], "123");
        assert!(row["decimals"].is_null());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].pool_contract_id, "pool");
        assert_eq!(errors[0].error, "offline");
        assert!(
            portfolio_rows(
                &balances(),
                &[],
                &Explorer::new(""),
                &Default::default(),
                &Default::default()
            )
            .0
            .is_empty()
        );
    }

    #[test]
    fn a_pool_row_names_its_fee_smallest_deposit_and_max_to_send_in_token_units() {
        let (rows, errors) = portfolio_rows(
            &balances(),
            &[&entry()],
            &Explorer::new("https://example.test"),
            &[("pool".into(), Ok(7))].into(),
            &[(
                "pool".into(),
                Ok((pool_info(), NoteAmount::from(99_000u128))),
            )]
            .into(),
        );
        assert!(errors.is_empty());
        let row = serde_json::to_value(&rows[0]).expect("JSON");
        assert_eq!(row["pool_fee"], "0.0001 XLM");
        assert_eq!(row["pool_fee_base_units"], "1000");
        assert_eq!(row["smallest_deposit"], "0.001 XLM");
        assert_eq!(row["smallest_deposit_base_units"], "10000");
        assert_eq!(row["max_to_send"], "0.0099 XLM");
        assert_eq!(row["max_to_send_base_units"], "99000");
    }

    #[test]
    fn a_limits_failure_keeps_the_balance_and_reports_a_pool_error() {
        let (rows, errors) = portfolio_rows(
            &balances(),
            &[&entry()],
            &Explorer::new("https://example.test"),
            &[("pool".into(), Ok(7))].into(),
            &[("pool".into(), Err(anyhow::anyhow!("offline")))].into(),
        );
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).expect("JSON");
        assert_eq!(row["balance"], "0.0000123 XLM");
        assert!(row.get("pool_fee").is_none());
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].error,
            "pool fee, smallest deposit and max to send unavailable: offline"
        );
    }
}

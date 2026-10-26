//! `overview` — dashboard-style view of pools, balances, contracts, network,
//! and this account's registration status.

use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use serde::Serialize;
use stellar_private_payments::types::{
    AssetDescriptor, ContractConfig, GvkMode, POLICY_FLAGS_IN_SUFFIX_ORDER, PolicyFlags,
};

use crate::{
    code_status::{self, Code, CodeStatus, Expected},
    config::{CliConfig, ManifestExtras, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::ClientSession,
    stellar_cli::{self, ContractCode, StellarNetwork},
};

const VERIFIER_PACKAGE: &str = "circom-groth16-verifier";

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
    policy_flags: PolicyFlags,
    gvk_mode: GvkMode,
    balance: String,
    balance_base_units: String,
    decimals: Option<u32>,
}

#[derive(Serialize)]
struct PoolErrorRow {
    pool_contract_id: String,
    error: String,
}

#[derive(Serialize)]
struct CodeRow {
    role: String,
    contract_id: String,
    link: String,
    #[serde(flatten)]
    status: CodeStatus,
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
    contracts: Vec<CodeRow>,
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
            let precision = session.token_decimals(
                portfolio
                    .iter()
                    .map(|balance| balance.pool_contract_id.as_str())
                    .filter(|id| allowed.contains(id)),
            );
            (pools, errors) = portfolio_rows(&portfolio, &entries, &explorer, &precision);
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
        contracts: code_rows(config, &network, &explorer),
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
        output::print_kv(
            "  controls",
            controls_label(pool.policy_flags, pool.gvk_mode),
        );
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

    println!();
    output::print_section("Contract code");
    println!(
        "Where each contract's code was built, from GitHub's build records. A build record says \
         where the code came from, not that it is safe. Showing this section sends a fingerprint \
         of each contract's code, and your IP address, to GitHub."
    );
    for row in &o.contracts {
        output::print_kv(&row.role, format!("{} → {}", row.contract_id, row.link));
        output::print_kv("  build record", &row.status);
    }
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

/// One row per contract the manifest names. Each contract is read once and
/// each distinct Wasm looked up once, in parallel.
fn code_rows(config: &CliConfig, network: &StellarNetwork, explorer: &Explorer) -> Vec<CodeRow> {
    let named = contract_rows(&config.deployment, &config.manifest);
    let config_dir = config.stellar_config_dir.as_deref();
    let codes: HashMap<&str, Option<Option<ContractCode>>> = std::thread::scope(|scope| {
        let reads: Vec<_> = named
            .iter()
            .map(|(_, id, _)| *id)
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|id| {
                let read = scope.spawn(move || stellar_cli::contract_code(id, network, config_dir));
                (id, read)
            })
            .collect();
        reads
            .into_iter()
            .map(|(id, read)| {
                let code = read
                    .join()
                    .unwrap_or_else(|_| Err(anyhow!("the read stopped")))
                    .inspect_err(|error| {
                        log::warn!("could not read the code of contract {id}: {error:#}");
                    })
                    .ok();
                (id, code)
            })
            .collect()
    });
    let rows: Vec<_> = named
        .iter()
        .map(|(_, id, want)| {
            let code = match codes.get(id).and_then(Option::as_ref) {
                Some(Some(code)) => Code::Wasm(code),
                Some(None) => Code::NoWasm,
                None => Code::Unread,
            };
            (want, code)
        })
        .collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let client = code_status::client(code_status::GITHUB_TIMEOUT);
    let fetch = |url: &str| {
        let client = client.as_ref().map_err(|error| anyhow!("{error:#}"))?;
        code_status::fetch(client, url)
    };
    let statuses = code_status::statuses(&rows, &config.data_dir.join("code-status"), now, fetch);
    named
        .iter()
        .zip(statuses)
        .map(|((role, id, _), status)| CodeRow {
            role: role.clone(),
            contract_id: (*id).to_owned(),
            link: explorer.contract(id),
            status,
        })
        .collect()
}

/// Returns each contract the manifest names, with its role and the code it
/// must run.
fn contract_rows<'a>(
    dep: &'a ContractConfig,
    manifest: &'a ManifestExtras,
) -> Vec<(String, &'a str, Expected<'a>)> {
    let release = &manifest.contracts_release;
    let mut named = Vec::new();
    // Without a release entry, the hash deploy.sh records for the role, if any.
    let mut push = |role: &str, id: &'a str, package, key, role_hash: Option<&'a String>| {
        let recorded = release.code.get(id).or(role_hash).map(String::as_str);
        let network = release.network.as_deref();
        named.push((
            role.to_owned(),
            id,
            Expected {
                recorded,
                package,
                key,
                network,
            },
        ));
    };
    for pool in &dep.pools {
        let package = match pool.gvk_mode {
            GvkMode::Off => "pool",
            GvkMode::ViewOnly | GvkMode::Traceable => "pool-gvk",
        };
        push("pool", &pool.pool_contract_id, package, None, None);
    }
    let allowlist = manifest.asp_membership_wasm_hash.as_ref();
    push(
        "asp_membership",
        &dep.asp_membership,
        "asp-membership",
        None,
        allowlist,
    );
    for tree in &dep.added_asp_memberships {
        push(
            "added_asp_membership",
            &tree.contract_id,
            "asp-membership",
            None,
            allowlist,
        );
    }
    let blocklist = manifest.asp_non_membership_wasm_hash.as_ref();
    push(
        "asp_non_membership",
        &dep.asp_non_membership,
        "asp-non-membership",
        None,
        blocklist,
    );
    push(
        "public_key_registry",
        &dep.public_key_registry,
        "public-key-registry",
        None,
        None,
    );
    if let Some(id) = &manifest.public_key_registry_verifier {
        let hash = manifest.public_key_registry_verifier_wasm_hash.as_ref();
        push(
            "public_key_registry_verifier",
            id,
            VERIFIER_PACKAGE,
            Some("keyOwnership"),
            hash,
        );
    }
    for (key, id) in &dep.verifiers {
        let role = format!("verifier.{}", if key.is_empty() { "none" } else { key });
        push(&role, id, VERIFIER_PACKAGE, Some(key), None);
    }
    named
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

/// Pool controls as shown in human output: ASP flags (or `open` when none are
/// set), then the admin view key mode when enabled.
fn controls_label(flags: PolicyFlags, gvk_mode: GvkMode) -> String {
    let mut controls: Vec<&str> = POLICY_FLAGS_IN_SUFFIX_ORDER
        .iter()
        .filter(|flag| flags.contains(**flag))
        .map(|flag| flag.name())
        .collect();
    if controls.is_empty() {
        controls.push("open");
    }
    match gvk_mode {
        GvkMode::Off => {}
        GvkMode::ViewOnly => controls.push("admin view key (view-only)"),
        GvkMode::Traceable => controls.push("admin view key (traceable)"),
    }
    controls.join(", ")
}

fn portfolio_rows(
    portfolio: &[stellar_private_payments::types::PortfolioBalance],
    entries: &[&stellar_private_payments::types::PoolConfigEntry],
    explorer: &Explorer,
    precision: &std::collections::HashMap<String, Result<u32>>,
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
        pools.push(PoolRow {
            pool_contract_id: balance.pool_contract_id.clone(),
            pool_link: explorer.contract(&balance.pool_contract_id),
            token_contract_id: entry.token_contract_id.clone(),
            token_link: explorer.contract(&entry.token_contract_id),
            asset: asset_label(&entry.asset),
            policy_flags: entry.policy_flags,
            gvk_mode: entry.gvk_mode,
            balance_base_units: balance.amount.to_string(),
            decimals,
            balance: output::format_token_amount(
                u128::from(balance.amount),
                &asset_symbol(&entry.asset),
                decimals,
            ),
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
    use crate::config::ContractsRelease;
    use stellar_private_payments::types::{NoteAmount, PoolConfigEntry, PortfolioBalance};

    fn pool_entry(id: &str, policy_flags: PolicyFlags, gvk_mode: GvkMode) -> PoolConfigEntry {
        PoolConfigEntry {
            pool_contract_id: id.into(),
            token_contract_id: "token".into(),
            deployment_ledger: 0,
            enabled: true,
            asset: AssetDescriptor::Native,
            policy_flags,
            gvk_mode,
            gvk_authority_pub_key: None,
        }
    }

    fn balance(id: &str) -> PortfolioBalance {
        PortfolioBalance {
            pool_contract_id: id.into(),
            token_contract_id: "token".into(),
            token_label: "XLM".into(),
            amount: NoteAmount::from(1u128),
            note_count: 1,
        }
    }

    #[test]
    fn metadata_failure_keeps_balance_and_reports_pool_error() {
        let entry = serde_json::from_value(serde_json::json!({
            "poolContractId": "pool", "tokenContractId": "token", "enabled": true,
            "deploymentLedger": 0, "policyFlags": [], "asset": {"kind": "native"}
        }))
        .expect("pool");
        let balances = [PortfolioBalance {
            pool_contract_id: "pool".into(),
            token_contract_id: "token".into(),
            token_label: "XLM".into(),
            amount: NoteAmount::from(123u128),
            note_count: 1,
        }];
        let (rows, errors) = portfolio_rows(
            &balances,
            &[&entry],
            &Explorer::new("https://example.test"),
            &[("pool".into(), Err(anyhow::anyhow!("offline")))].into(),
        );
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).expect("JSON");
        assert_eq!(row["balance"], "123 base units");
        assert_eq!(row["balance_base_units"], "123");
        assert!(row["decimals"].is_null());
        assert_eq!(row["policy_flags"], serde_json::json!([]));
        assert_eq!(row["gvk_mode"], "off");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].pool_contract_id, "pool");
        assert_eq!(errors[0].error, "offline");
        assert!(
            portfolio_rows(&balances, &[], &Explorer::new(""), &Default::default())
                .0
                .is_empty()
        );
    }

    #[test]
    fn portfolio_rows_carry_pool_controls() {
        let traceable = pool_entry(
            "traceable",
            PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
            GvkMode::Traceable,
        );
        let view_only = pool_entry("view-only", PolicyFlags::BLOCKLIST, GvkMode::ViewOnly);
        let (rows, errors) = portfolio_rows(
            &[balance("traceable"), balance("view-only")],
            &[&traceable, &view_only],
            &Explorer::new("https://example.test"),
            &Default::default(),
        );
        assert!(errors.is_empty());
        assert_eq!(rows.len(), 2);
        let rows = serde_json::to_value(&rows).expect("JSON");
        assert_eq!(
            rows[0]["policy_flags"],
            serde_json::json!(["allowlist", "blocklist"])
        );
        assert_eq!(rows[0]["gvk_mode"], "traceable");
        assert_eq!(rows[1]["policy_flags"], serde_json::json!(["blocklist"]));
        assert_eq!(rows[1]["gvk_mode"], "viewOnly");
    }

    #[test]
    fn contract_rows_name_each_contract_with_its_role() {
        let pool = |id: &str| {
            serde_json::json!({
                "poolContractId": id, "tokenContractId": "token", "enabled": true,
                "deploymentLedger": 0, "policyFlags": [], "asset": {"kind": "native"},
            })
        };
        let mut gvk = pool("CGVK");
        gvk["gvkMode"] = "viewOnly".into();
        let dep: ContractConfig = serde_json::from_value(serde_json::json!({
            "network": "testnet", "kdf_domain": "d", "deployer": "G", "admin": "G",
            "pools": [pool("CPOOL"), gvk],
            "asp_membership": "CALLOW",
            "added_asp_memberships": [{ "contractId": "CADDED", "deploymentLedger": 1 }],
            "asp_non_membership": "CBLOCK",
            "verifiers": { "": "CNONE", "B": "CB" },
            "public_key_registry": "CREG",
        }))
        .expect("deployment");
        let mut manifest = ManifestExtras {
            asp_membership_wasm_hash: Some("allow".into()),
            asp_non_membership_wasm_hash: Some("block".into()),
            public_key_registry_verifier: Some("CREGV".into()),
            public_key_registry_verifier_wasm_hash: Some("regv".into()),
            ..Default::default()
        };
        let rows = contract_rows(&dep, &manifest);
        let roles: Vec<_> = rows
            .iter()
            .map(|(role, id, _)| (role.as_str(), *id))
            .collect();
        assert_eq!(
            roles,
            [
                ("pool", "CPOOL"),
                ("pool", "CGVK"),
                ("asp_membership", "CALLOW"),
                ("added_asp_membership", "CADDED"),
                ("asp_non_membership", "CBLOCK"),
                ("public_key_registry", "CREG"),
                ("public_key_registry_verifier", "CREGV"),
                ("verifier.none", "CNONE"),
                ("verifier.B", "CB"),
            ]
        );
        // What a manifest with a field of the wrong type loads as.
        let unread = ManifestExtras::default();
        let bare: Vec<_> = contract_rows(&dep, &unread)
            .into_iter()
            .map(|(role, _, want)| (role, want.recorded, want.network))
            .collect();
        let expected: Vec<_> = roles
            .iter()
            .filter(|(role, _)| *role != "public_key_registry_verifier")
            .map(|(role, _)| ((*role).to_owned(), None, None))
            .collect();
        assert_eq!(bare, expected);
        let packages: Vec<_> = rows.iter().map(|(_, _, want)| want.package).collect();
        assert_eq!(
            &packages[..6],
            [
                "pool",
                "pool-gvk",
                "asp-membership",
                "asp-membership",
                "asp-non-membership",
                "public-key-registry",
            ]
        );
        assert!(
            packages[6..]
                .iter()
                .all(|package| *package == VERIFIER_PACKAGE)
        );
        let keys: Vec<_> = rows.iter().map(|(_, _, want)| want.key).collect();
        assert_eq!(keys[6..], [Some("keyOwnership"), Some(""), Some("B")]);
        assert!(keys[..6].iter().all(Option::is_none));
        let recorded: Vec<_> = rows.iter().map(|(_, _, want)| want.recorded).collect();
        let (allow, block, regv) = (Some("allow"), Some("block"), Some("regv"));
        let unreleased = [None, None, allow, allow, block, None, regv, None, None];
        assert_eq!(recorded, unreleased);
        manifest.contracts_release = ContractsRelease {
            network: Some("testnet".into()),
            code: [("CB", "released"), ("CALLOW", "released")]
                .map(|(id, hash)| (id.into(), hash.into()))
                .into(),
        };
        let released = contract_rows(&dep, &manifest);
        let recorded: Vec<_> = released.iter().map(|(_, _, want)| want.recorded).collect();
        let release = Some("released");
        let mixed = [None, None, release, allow, block, None, regv, None, release];
        assert_eq!(recorded, mixed);
        assert!(
            released
                .iter()
                .all(|(_, _, want)| want.network == Some("testnet"))
        );
    }

    #[test]
    fn controls_label_formats_flags_and_gvk() {
        let both = PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST;
        let cases = [
            (PolicyFlags::EMPTY, GvkMode::Off, "open"),
            (PolicyFlags::BLOCKLIST, GvkMode::Off, "blocklist"),
            (PolicyFlags::ALLOWLIST, GvkMode::Off, "allowlist"),
            (both, GvkMode::Off, "allowlist, blocklist"),
            (
                PolicyFlags::BLOCKLIST,
                GvkMode::Traceable,
                "blocklist, admin view key (traceable)",
            ),
            (
                PolicyFlags::BLOCKLIST,
                GvkMode::ViewOnly,
                "blocklist, admin view key (view-only)",
            ),
            (
                PolicyFlags::EMPTY,
                GvkMode::ViewOnly,
                "open, admin view key (view-only)",
            ),
            (
                PolicyFlags::EMPTY,
                GvkMode::Traceable,
                "open, admin view key (traceable)",
            ),
        ];
        for (flags, gvk_mode, expected) in cases {
            assert_eq!(controls_label(flags, gvk_mode), expected);
        }
    }
}

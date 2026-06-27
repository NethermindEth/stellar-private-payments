use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::{
    config::{CliConfig, write_config_template},
    output,
};

#[derive(Serialize)]
struct ConfigShow<'a> {
    config_file: Option<&'a str>,
    deployment_path: &'a str,
    network: &'a str,
    rpc_url: &'a str,
    data_dir: &'a str,
    wallet_db: &'a str,
    account: Option<&'a str>,
    account_index: u32,
    asp_membership: &'a str,
    asp_non_membership: &'a str,
    verifier: &'a str,
    public_key_registry: &'a str,
    enabled_pools: usize,
}

pub fn show(config: &CliConfig, json: bool) -> Result<()> {
    let config_file_display = config
        .config_file
        .as_ref()
        .map(|path| path.display().to_string());
    let payload = ConfigShow {
        config_file: config_file_display.as_deref(),
        deployment_path: &config.deployment_source,
        network: &config.deployment.network,
        rpc_url: &config.rpc_url,
        data_dir: &config.data_dir.display().to_string(),
        wallet_db: &config.wallet_db_path().display().to_string(),
        account: config.account.as_deref(),
        account_index: config.account_index,
        asp_membership: &config.deployment.asp_membership,
        asp_non_membership: &config.deployment.asp_non_membership,
        verifier: &config.deployment.verifier,
        public_key_registry: &config.deployment.public_key_registry,
        enabled_pools: config
            .deployment
            .pools
            .iter()
            .filter(|pool| pool.enabled)
            .count(),
    };

    if json {
        output::emit(&payload, true)?;
        return Ok(());
    }

    output::print_section("Resolved configuration");
    if let Some(config_file) = payload.config_file {
        output::print_kv("config_file", config_file);
    }
    output::print_kv("deployment", payload.deployment_path);
    output::print_kv("network", payload.network);
    output::print_kv("rpc_url", payload.rpc_url);
    output::print_kv("data_dir", payload.data_dir);
    output::print_kv("wallet_db", payload.wallet_db);
    if let Some(account) = payload.account {
        output::print_kv("account", account);
    }
    output::print_kv("account_index", payload.account_index);
    output::print_kv("asp_membership", payload.asp_membership);
    output::print_kv("asp_non_membership", payload.asp_non_membership);
    output::print_kv("verifier", payload.verifier);
    output::print_kv("public_key_registry", payload.public_key_registry);
    output::print_kv("enabled_pools", payload.enabled_pools);
    Ok(())
}

pub fn init(path: &Path, json: bool) -> Result<()> {
    write_config_template(path)?;

    let config_file = path.display().to_string();

    #[derive(Serialize)]
    struct InitOut<'a> {
        config_file: &'a str,
        message: &'a str,
    }

    let payload = InitOut {
        config_file: &config_file,
        message: "config template written",
    };

    if json {
        output::emit(&payload, true)?;
        return Ok(());
    }

    output::print_section("Config initialized");
    output::print_kv("config_file", payload.config_file);
    println!("Edit the file, then run `stellar-pp config show` to verify.");
    Ok(())
}

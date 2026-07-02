//! `config` — inspect resolved config, write a template, and update the
//! explorer / bootnode settings stored in the local database.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::{
    config::{CliConfig, write_config_template},
    explorer, output,
};

pub fn show(config: &CliConfig, json: bool) -> Result<()> {
    let storage = config.open_storage()?;
    let explorer_base = explorer::base_url(&storage)?;
    let bootnode = storage.get_bootnode_setting()?;
    // RPC resolution is best-effort (needs the Stellar CLI network config).
    let (rpc_url, network_passphrase) = match config.resolve_network() {
        Ok(net) => (Some(net.rpc_url), Some(net.passphrase)),
        Err(_) => (None, None),
    };

    let config_file = config.config_file.as_ref().map(|p| p.display().to_string());
    let data_dir = config.data_dir.display().to_string();
    let db = config.db_path().display().to_string();

    #[derive(Serialize)]
    struct ConfigShow<'a> {
        config_file: Option<&'a str>,
        deployment: &'a str,
        network: &'a str,
        rpc_url: Option<&'a str>,
        network_passphrase: Option<&'a str>,
        data_dir: &'a str,
        database: &'a str,
        source_account: Option<&'a str>,
        explorer_base_url: &'a str,
        bootnode_enabled: bool,
        bootnode_url: &'a str,
        asp_membership: &'a str,
        asp_non_membership: &'a str,
        verifier: &'a str,
        public_key_registry: &'a str,
        enabled_pools: usize,
    }
    let payload = ConfigShow {
        config_file: config_file.as_deref(),
        deployment: &config.deployment_source,
        network: &config.network,
        rpc_url: rpc_url.as_deref(),
        network_passphrase: network_passphrase.as_deref(),
        data_dir: &data_dir,
        database: &db,
        source_account: config.source_account.as_deref(),
        explorer_base_url: &explorer_base,
        bootnode_enabled: bootnode.enabled,
        bootnode_url: &bootnode.url,
        asp_membership: &config.deployment.asp_membership,
        asp_non_membership: &config.deployment.asp_non_membership,
        verifier: &config.deployment.verifier,
        public_key_registry: &config.deployment.public_key_registry,
        enabled_pools: config.deployment.pools.iter().filter(|p| p.enabled).count(),
    };

    if json {
        return output::emit(&payload, true);
    }

    output::print_section("Resolved configuration");
    if let Some(config_file) = payload.config_file {
        output::print_kv("config_file", config_file);
    }
    output::print_kv("deployment", payload.deployment);
    output::print_kv("network", payload.network);
    output::print_kv("rpc_url", payload.rpc_url.unwrap_or("(unresolved)"));
    output::print_kv(
        "network_passphrase",
        payload.network_passphrase.unwrap_or("(unresolved)"),
    );
    output::print_kv("data_dir", payload.data_dir);
    output::print_kv("database", payload.database);
    if let Some(source_account) = payload.source_account {
        output::print_kv("source_account", source_account);
    }
    output::print_kv("explorer_base_url", payload.explorer_base_url);
    output::print_kv(
        "bootnode",
        if payload.bootnode_enabled {
            payload.bootnode_url
        } else {
            "(disabled)"
        },
    );
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
        return output::emit(&payload, true);
    }
    output::print_section("Config initialized");
    output::print_kv("config_file", payload.config_file);
    println!("Edit the file, then run `spp config show` to verify.");
    Ok(())
}

pub fn set_explorer(config: &CliConfig, url: &str, json: bool) -> Result<()> {
    let mut storage = config.open_storage()?;
    explorer::set_base_url(&mut storage, url)?;
    report_setting(json, "explorer_base_url", url)
}

pub fn set_bootnode(
    config: &CliConfig,
    url: Option<&str>,
    disable: bool,
    json: bool,
) -> Result<()> {
    let mut storage = config.open_storage()?;
    if disable {
        storage.set_bootnode_setting(false, "")?;
        return report_setting(json, "bootnode", "(disabled)");
    }
    let url = url.ok_or_else(|| anyhow::anyhow!("provide a bootnode URL, or pass --disable"))?;
    storage.set_bootnode_setting(true, url)?;
    report_setting(json, "bootnode", url)
}

fn report_setting(json: bool, key: &str, value: &str) -> Result<()> {
    #[derive(Serialize)]
    struct SettingOut<'a> {
        setting: &'a str,
        value: &'a str,
    }
    if json {
        return output::emit(
            &SettingOut {
                setting: key,
                value,
            },
            true,
        );
    }
    output::print_section("Setting updated");
    output::print_kv(key, value);
    Ok(())
}

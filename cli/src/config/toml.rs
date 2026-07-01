use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// User settings loaded from a TOML file (`~/.config/spp/config.toml` by
/// default).
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub defaults: DefaultsSection,
    #[serde(default)]
    pub wallet: WalletSection,
}

#[derive(Debug, Default, Deserialize)]
pub struct DefaultsSection {
    pub deployment: Option<PathBuf>,
    pub rpc_url: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub circuits_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WalletSection {
    pub account_index: Option<u32>,
    pub account: Option<String>,
    pub mnemonic: Option<String>,
    pub mnemonic_passphrase: Option<String>,
}

pub const CONFIG_TEMPLATE: &str = r#"# Stellar Private Payments CLI configuration

[defaults]
# deployment = "/path/to/deployments.json"  # omit for embedded testnet
# rpc_url = "https://soroban-testnet.stellar.org"
# data_dir = "~/.local/share/stellar-private-payments"
# circuits_dir = "target/circuits-artifacts/release"

[wallet]
# account_index = 0   # SEP-5: m/44'/148'/INDEX' (Freighter: 1st account = 0, 2nd = 1, …)
# account = "G..."    # optional: expected address for validation only
# mnemonic = "word1 word2 ..."
# mnemonic_passphrase = ""  # optional BIP39 passphrase (Freighter “password”)
"#;

pub fn default_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/spp/config.toml"))
        .unwrap_or_else(|| PathBuf::from("spp.toml"))
}

pub fn resolve_config_path(cli_path: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = cli_path {
        return Some(path);
    }
    if let Ok(path) = std::env::var("STELLAR_PP_CONFIG") {
        return Some(PathBuf::from(path));
    }
    let path = default_config_path();
    path.is_file().then_some(path)
}

pub fn load_file_config(path: &Path) -> Result<FileConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parse config file {}", path.display()))
}

pub fn expand_path(path: PathBuf) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path;
    };
    let Some(rest) = raw.strip_prefix("~/") else {
        return path;
    };
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(rest))
        .unwrap_or(path)
}

pub fn write_config_template(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!(
            "config file already exists at {}; remove it first or pass --config to another path",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }
    std::fs::write(path, CONFIG_TEMPLATE)
        .with_context(|| format!("write config template {}", path.display()))
}

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// User settings loaded from a TOML file (`~/.config/spp/config.toml` by
/// default).
///
/// Accounts and the network (RPC URL + passphrase) are managed by the Stellar
/// CLI, and the explorer/bootnode settings live in the local database — so this
/// file only carries offline `[defaults]`.
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub defaults: DefaultsSection,
}

#[derive(Debug, Default, Deserialize)]
pub struct DefaultsSection {
    pub deployment: Option<PathBuf>,
    /// Stellar CLI network name (default: the deployment's network).
    pub network: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub circuits_dir: Option<PathBuf>,
    pub stellar_config_dir: Option<PathBuf>,
}

const DEFAULT_DATA_DIR_TEMPLATE: &str = "~/.local/share/stellar-private-payments";
fn config_template() -> String {
    format!(
        r#"# Stellar Private Payments CLI configuration
# Accounts and named networks are managed by Stellar CLI.
[defaults]
# deployment = "/path/to/deployment" # directory or deployments.json; required unless provisioned in data_dir
# network = "testnet" # optional Stellar CLI name; defaults to deployment.network
# data_dir = "{DEFAULT_DATA_DIR_TEMPLATE}"
# circuits_dir = "/path/to/artifacts" # optional; packaged circuits/ or repo target/circuits-artifacts, with circuit_keys/ fallback
# stellar_config_dir = "~/.config/stellar"
"#
    )
}

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
    std::fs::write(path, config_template())
        .with_context(|| format!("write config template {}", path.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn template_explains_required_deployment() {
        assert!(super::config_template().contains("required unless provisioned"));
        assert!(!super::config_template().contains("embedded"));
    }
}

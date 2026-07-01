mod toml;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use stellar_private_payments_sdk::{state::SqliteStorage, types::ContractConfig};

use crate::{
    account::{Account, resolve},
    stellar_cli::{self, StellarNetwork},
};

pub use toml::{
    FileConfig, default_config_path, load_file_config, resolve_config_path, write_config_template,
};

/// Testnet deployment baked into the binary (from
/// `deployments/testnet/deployments.json`).
pub const DEFAULT_DEPLOYMENT_JSON: &str =
    include_str!("../../../deployments/testnet/deployments.json");

pub const EMBEDDED_DEPLOYMENT_LABEL: &str = "embedded:testnet";

/// CLI flag overrides used to build a [`CliConfig`].
#[derive(Debug, Default)]
pub struct CliConfigOverrides {
    pub deployment_path: Option<PathBuf>,
    pub network: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub source_account: Option<String>,
    pub stellar_config_dir: Option<PathBuf>,
    pub circuits_dir: Option<PathBuf>,
}

/// Resolved (offline) CLI configuration.
///
/// Loading never calls the `stellar` binary; the RPC/passphrase (via
/// [`CliConfig::resolve_network`]) and the signing account (via
/// [`CliConfig::require_account`]) are resolved on demand by the commands that
/// need them.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// TOML config file when loaded; otherwise None.
    pub config_file: Option<PathBuf>,
    /// File path when overridden; otherwise [`EMBEDDED_DEPLOYMENT_LABEL`].
    pub deployment_source: String,
    pub deployment: ContractConfig,
    /// Stellar CLI network name (built-in like `testnet`, or a custom one).
    pub network: String,
    pub data_dir: PathBuf,
    /// Config dir passed through to the `stellar` CLI (`--config-dir`).
    pub stellar_config_dir: Option<PathBuf>,
    /// `stellar keys` alias supplied via `--source-account`.
    pub source_account: Option<String>,
    pub circuits_dir: Option<PathBuf>,
}

impl CliConfig {
    pub fn load(
        config_file: Option<PathBuf>,
        file: Option<FileConfig>,
        overrides: CliConfigOverrides,
    ) -> Result<Self> {
        let file = file.unwrap_or_default();
        let CliConfigOverrides {
            deployment_path,
            network,
            data_dir,
            source_account,
            stellar_config_dir,
            circuits_dir,
        } = overrides;

        let deployment_path = deployment_path.or(file.defaults.deployment.map(toml::expand_path));
        let data_dir = data_dir
            .or(file.defaults.data_dir.map(toml::expand_path))
            .unwrap_or_else(default_data_dir);
        let circuits_dir = circuits_dir.or(file.defaults.circuits_dir.map(toml::expand_path));
        let stellar_config_dir =
            stellar_config_dir.or(file.defaults.stellar_config_dir.map(toml::expand_path));

        let (deployment_source, deployment) = load_deployment(deployment_path.as_deref())?;
        // Network name: --network > config default > the deployment's network
        // (which matches a Stellar CLI built-in like `testnet`).
        let network = network
            .or(file.defaults.network)
            .unwrap_or_else(|| deployment.network.clone());

        Ok(Self {
            config_file,
            deployment_source,
            deployment,
            network,
            data_dir,
            stellar_config_dir,
            source_account,
            circuits_dir,
        })
    }

    /// Resolve the RPC URL + network passphrase from the Stellar CLI.
    pub fn resolve_network(&self) -> Result<StellarNetwork> {
        stellar_cli::network(&self.network, self.stellar_config_dir.as_deref())
    }

    /// Resolve the signing account from its `--source-account` alias.
    pub fn require_account(&self) -> Result<Account> {
        let alias = self.source_account.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "this command requires --source-account <stellar keys alias> \
                 (spp works with Stellar CLI identities; see `stellar keys`)"
            )
        })?;
        resolve(alias, self.stellar_config_dir.as_deref())
    }

    pub fn wallet_db_path(&self) -> PathBuf {
        self.data_dir.join("spp.db")
    }

    /// Open (creating if needed) the local sqlite database (`spp.db`).
    pub fn open_storage(&self) -> Result<SqliteStorage> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("create data dir {}", self.data_dir.display()))?;
        let path = self.wallet_db_path();
        SqliteStorage::connect_file(&path).with_context(|| format!("open {}", path.display()))
    }
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/share/stellar-private-payments"))
        .unwrap_or_else(|| PathBuf::from(".stellar-pp"))
}

fn load_deployment(path: Option<&Path>) -> Result<(String, ContractConfig)> {
    match path {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read deployment file {}", path.display()))?;
            let deployment = serde_json::from_str(&raw)
                .with_context(|| format!("parse deployment file {}", path.display()))?;
            Ok((path.display().to_string(), deployment))
        }
        None => {
            let deployment = serde_json::from_str(DEFAULT_DEPLOYMENT_JSON)
                .context("parse embedded testnet deployment")?;
            Ok((EMBEDDED_DEPLOYMENT_LABEL.to_string(), deployment))
        }
    }
}

pub fn validate_pool(pool: &str, deployment: &ContractConfig) -> Result<()> {
    if deployment
        .pools
        .iter()
        .any(|entry| entry.pool_contract_id == pool && entry.enabled)
    {
        Ok(())
    } else {
        bail!("pool {pool} is not an enabled pool in the deployment config");
    }
}

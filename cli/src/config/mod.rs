mod toml;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use stellar_private_payments_sdk::types::ContractConfig;

use crate::signing::WalletCredentials;

pub use toml::{
    FileConfig, default_config_path, load_file_config, resolve_config_path, write_config_template,
};

/// Testnet deployment baked into the binary (from
/// `deployments/testnet/deployments.json`).
pub const DEFAULT_DEPLOYMENT_JSON: &str =
    include_str!("../../../deployments/testnet/deployments.json");

pub const EMBEDDED_DEPLOYMENT_LABEL: &str = "embedded:testnet";

/// CLI flag overrides used to build a [`CliConfig`].
#[derive(Debug)]
pub struct CliConfigOverrides {
    pub deployment_path: Option<PathBuf>,
    pub rpc_url: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub account: Option<String>,
    pub secret: Option<String>,
    pub mnemonic: Option<String>,
    pub mnemonic_passphrase: Option<String>,
    pub account_index: Option<u32>,
    pub circuits_dir: Option<PathBuf>,
}

/// CLI global flags used to build a [`CliConfig`].
#[derive(Debug)]
pub struct CliConfigLoad {
    pub deployment_path: Option<PathBuf>,
    pub rpc_url: Option<String>,
    pub data_dir: PathBuf,
    pub account: Option<String>,
    pub secret: Option<String>,
    pub mnemonic: Option<String>,
    pub mnemonic_passphrase: Option<String>,
    pub account_index: u32,
    pub circuits_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    /// TOML config file when loaded; otherwise None.
    pub config_file: Option<PathBuf>,
    /// File path when overridden; otherwise [`EMBEDDED_DEPLOYMENT_LABEL`].
    pub deployment_source: String,
    pub deployment: ContractConfig,
    pub rpc_url: String,
    pub data_dir: PathBuf,
    pub account_index: u32,
    /// Explicit `--account`, or the address derived from `--secret` /
    /// `--mnemonic`.
    pub account: Option<String>,
    /// Resolved signing material when `--secret` or `--mnemonic` is provided.
    pub wallet: Option<WalletCredentials>,
    pub pool: Option<String>,
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
            rpc_url,
            data_dir,
            account,
            secret,
            mnemonic,
            mnemonic_passphrase,
            account_index,
            circuits_dir,
        } = overrides;

        let deployment_path = deployment_path.or(file.defaults.deployment.map(toml::expand_path));
        let data_dir = data_dir
            .or(file.defaults.data_dir.map(toml::expand_path))
            .unwrap_or_else(default_data_dir);
        let rpc_url = rpc_url.or(file.defaults.rpc_url);
        let circuits_dir = circuits_dir.or(file.defaults.circuits_dir.map(toml::expand_path));

        let account_index = account_index.or(file.wallet.account_index).unwrap_or(0);
        let account = account.or(file.wallet.account);

        let mnemonic = mnemonic.or(file.wallet.mnemonic);
        let mnemonic_passphrase = mnemonic_passphrase.or(file.wallet.mnemonic_passphrase);

        let load = CliConfigLoad {
            deployment_path,
            rpc_url,
            data_dir,
            account,
            secret,
            mnemonic,
            mnemonic_passphrase,
            account_index,
            circuits_dir,
        };
        Self::from_resolved(config_file, load)
    }

    fn from_resolved(config_file: Option<PathBuf>, input: CliConfigLoad) -> Result<Self> {
        let CliConfigLoad {
            deployment_path,
            rpc_url,
            data_dir,
            account,
            secret,
            mnemonic,
            mnemonic_passphrase,
            account_index,
            circuits_dir,
        } = input;
        let (deployment_source, deployment) = load_deployment(deployment_path.as_deref())?;
        let rpc_url = rpc_url.unwrap_or_else(|| default_rpc_url(&deployment.network));
        let wallet = crate::signing::resolve_wallet(
            secret.as_deref(),
            mnemonic.as_deref(),
            mnemonic_passphrase.as_deref(),
            account.as_deref(),
            account_index,
        )?;
        let account = account.or_else(|| wallet.as_ref().map(|w| w.address.clone()));
        Ok(Self {
            config_file,
            deployment_source,
            deployment,
            rpc_url,
            data_dir,
            account_index,
            account,
            wallet,
            pool: None,
            circuits_dir,
        })
    }

    pub fn require_wallet(&self) -> Result<&WalletCredentials> {
        self.wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pool commands require --secret or --mnemonic"))
    }

    pub fn require_pool(&self) -> Result<&str> {
        self.pool
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("pool id required"))
    }

    pub fn with_pool(mut self, pool_id: String) -> Self {
        self.pool = Some(pool_id);
        self
    }

    pub fn network_passphrase(&self) -> &'static str {
        network_passphrase_for(&self.deployment.network)
    }

    pub fn wallet_db_path(&self) -> PathBuf {
        self.data_dir.join("wallet.sqlite")
    }
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/share/stellar-private-payments"))
        .unwrap_or_else(|| PathBuf::from(".spp"))
}

pub fn default_rpc_url(network: &str) -> String {
    match network {
        "mainnet" | "public" => "https://soroban.stellar.org".into(),
        _ => "https://soroban-testnet.stellar.org".into(),
    }
}

pub fn network_passphrase_for(network: &str) -> &'static str {
    match network {
        "mainnet" | "public" => "Public Global Stellar Network ; September 2015",
        _ => "Test SDF Network ; September 2015",
    }
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

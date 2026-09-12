//! A real local Stellar network (`stellar/quickstart`), booted via
//! `testcontainers` and deployed to via the repo's own `deploy.sh`.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use stellar_private_payments::types::ContractConfig;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::{process::Command, sync::OnceCell};

/// Network passphrase `stellar/quickstart --local` always uses.
pub const NETWORK_PASSPHRASE: &str = "Standalone Network ; February 2017";

const RPC_PORT: u16 = 8000;

/// The Stellar CLI's built-in `local` network alias resolves to
/// `http://localhost:8000`, so the container binds that fixed host port
/// instead of a random one.
const STELLAR_CLI_NETWORK: &str = "local";

static SHARED: OnceCell<LocalNetwork> = OnceCell::const_new();

/// A running `stellar/quickstart` local network container.
pub struct LocalNetwork {
    _container: ContainerAsync<GenericImage>,
    rpc_url: String,
}

impl LocalNetwork {
    /// Process-wide container, started once and reused by every test.
    /// Fixed host port, so call [`Self::deploy`] on it exactly once (see
    /// `tests::support::shared_deployment`).
    pub async fn shared() -> Result<&'static Self> {
        SHARED.get_or_try_init(Self::start).await
    }

    /// Start a fresh local network and wait until its RPC endpoint reports
    /// healthy.
    ///
    /// `--limits unlimited`: the default (and `--limits testnet`) write-entry
    /// cap rejects a pool deployment at production tree depths
    /// (`--pool-levels 20`, matching the checked-in circuit artifacts) with
    /// `TxSorobanInvalid`.
    pub async fn start() -> Result<Self> {
        let container = GenericImage::new("stellar/quickstart", "testing")
            .with_exposed_port(RPC_PORT.tcp())
            .with_cmd([
                "--local",
                "--enable",
                "rpc,horizon",
                "--limits",
                "unlimited",
            ])
            .with_mapped_port(RPC_PORT, RPC_PORT.tcp())
            .start()
            .await
            .context("start stellar/quickstart container")?;

        let network = Self {
            _container: container,
            rpc_url: format!("http://localhost:{RPC_PORT}/rpc"),
        };
        network.wait_healthy().await?;
        Ok(network)
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn wait_healthy(&self) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 60;

        let client = reqwest::Client::new();
        for _ in 0..MAX_ATTEMPTS {
            if let Ok(resp) = client
                .post(&self.rpc_url)
                .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "getHealth"}))
                .send()
                .await
                && let Ok(body) = resp.json::<Value>().await
                && body["result"]["status"] == "healthy"
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("local network RPC did not become healthy within {MAX_ATTEMPTS}s");
    }

    /// Fund `address` via the container's friendbot.
    ///
    /// Retries: friendbot can still 502/503 for a few seconds after
    /// `getHealth` already reports healthy.
    pub async fn fund(&self, address: &str) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 10;

        let url = format!("http://localhost:{RPC_PORT}/friendbot?addr={address}");
        let mut last_error = String::new();
        for _ in 0..MAX_ATTEMPTS {
            match reqwest::get(&url).await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    last_error = format!("{status}: {body}");
                }
                Err(e) => last_error = e.to_string(),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("friendbot funding failed for {address} after {MAX_ATTEMPTS} attempts: {last_error}");
    }

    /// Deploy the full contract set (no ASP policy flags) via
    /// `deployments/scripts/deploy.sh`. `deployer_secret` must already be
    /// funded (see [`Self::fund`]). Call at most once per network.
    pub async fn deploy(&self, deployer_secret: &str, max_deposit: u128) -> Result<ContractConfig> {
        let root = repo_root();
        ensure_local_vk_file(&root)?;
        deploy_native_asset(deployer_secret).await?;

        let output = Command::new(root.join("deployments/scripts/deploy.sh"))
            .arg(STELLAR_CLI_NETWORK)
            .args(["--deployer", deployer_secret])
            .args(["--asp-levels", "10"])
            .args(["--pool-levels", "20"])
            .args(["--max-deposit", &max_deposit.to_string()])
            .args(["--policy-flags", "none"])
            .current_dir(&root)
            .output()
            .await
            .context("run deployments/scripts/deploy.sh")?;

        if !output.status.success() {
            bail!(
                "deploy.sh failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // deploy.sh writes diagnostics to stderr and only the deployment JSON
        // to stdout.
        serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "parse deploy.sh output as ContractConfig: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }
}

/// A fresh `--local` network never instantiates the native XLM SAC (unlike
/// testnet/pubnet), so deposits fail simulation until this runs once.
async fn deploy_native_asset(deployer_secret: &str) -> Result<()> {
    let output = Command::new("stellar")
        .args(["contract", "asset", "deploy", "--asset", "native"])
        .args(["--source-account", deployer_secret])
        .args(["--network", STELLAR_CLI_NETWORK])
        .output()
        .await
        .context("run stellar contract asset deploy --asset native")?;
    if !output.status.success() {
        bail!(
            "stellar contract asset deploy --asset native failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests has a parent directory")
        .to_path_buf()
}

/// The circuit is network-independent, so this copies the checked-in
/// testnet vk in on first use rather than duplicating it under
/// `deployments/local/`.
fn ensure_local_vk_file(root: &Path) -> Result<()> {
    let dest_dir = root.join("deployments/local/circuit_keys");
    let dest = dest_dir.join("policy_tx_2_2_vk.json");
    if dest.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dest_dir).context("create deployments/local/circuit_keys")?;
    std::fs::copy(
        root.join("deployments/testnet/circuit_keys/policy_tx_2_2_vk.json"),
        &dest,
    )
    .context("copy policy_tx_2_2_vk.json for the local deployment")?;
    Ok(())
}

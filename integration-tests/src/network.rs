//! A real local Stellar network (`stellar/quickstart`), expected to already
//! be running (see `make integration-tests`), deployed to via the repo's
//! own `deploy.sh`.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use stellar_private_payments::types::ContractConfig;
use tokio::{process::Command, sync::OnceCell};

/// Network passphrase `stellar/quickstart --local` always uses.
pub const NETWORK_PASSPHRASE: &str = "Standalone Network ; February 2017";

const RPC_PORT: u16 = 8000;

/// The Stellar CLI's built-in `local` network alias resolves to
/// `http://localhost:8000`, matching the port `make integration-tests` maps.
const STELLAR_CLI_NETWORK: &str = "local";

static SHARED: OnceCell<LocalNetwork> = OnceCell::const_new();

/// A `stellar/quickstart` local network, already running externally.
pub struct LocalNetwork {
    rpc_url: String,
}

impl LocalNetwork {
    /// Process-wide handle, resolved once and reused by every test.
    pub async fn shared() -> Result<&'static Self> {
        SHARED.get_or_try_init(Self::start).await
    }

    /// Wait until the local network's RPC endpoint reports healthy.
    pub async fn start() -> Result<Self> {
        let network = Self {
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
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("build friendbot client")?;
        let url = format!("http://localhost:{RPC_PORT}/friendbot?addr={address}");
        let mut last_error = String::new();
        for _ in 0..MAX_ATTEMPTS {
            match client.get(&url).send().await {
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

    /// Deploy the full contract set via `deployments/scripts/deploy.sh`.
    /// Coordinated per configuration (see [`acquire_deploy_lock`]), so
    /// concurrent processes with the same args share one deployment.
    pub async fn deploy(
        &self,
        deployer_secret: &str,
        max_deposit: u128,
        asp_levels: u32,
        pool_levels: u32,
        policy_flags: &str,
    ) -> Result<ContractConfig> {
        let root = repo_root();
        deploy_native_asset(deployer_secret).await?;

        let key = format!("{max_deposit}-{asp_levels}-{pool_levels}-{policy_flags}");
        let _guard = acquire_deploy_lock(&key).await?;

        if let Ok(cached) = std::fs::read(deploy_cache_path(&key))
            && let Ok(config) = serde_json::from_slice(&cached)
        {
            return Ok(config);
        }

        let output = Command::new(root.join("deployments/scripts/deploy.sh"))
            .arg(STELLAR_CLI_NETWORK)
            .args(["--deployer", deployer_secret])
            .args(["--asp-levels", &asp_levels.to_string()])
            .args(["--pool-levels", &pool_levels.to_string()])
            .args(["--max-deposit", &max_deposit.to_string()])
            .args(["--policy-flags", policy_flags])
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
        let config: ContractConfig = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "parse deploy.sh output as ContractConfig: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })?;
        std::fs::write(deploy_cache_path(&key), &output.stdout).context("write deploy cache")?;
        Ok(config)
    }
}

/// A fresh `--local` network never instantiates the native XLM SAC (unlike
/// testnet/pubnet), so deposits fail simulation until this runs once.
async fn deploy_native_asset(deployer_secret: &str) -> Result<()> {
    const KEY: &str = "native-asset";
    let _guard = acquire_deploy_lock(KEY).await?;

    if deploy_cache_path(KEY).exists() {
        return Ok(());
    }

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
    std::fs::write(deploy_cache_path(KEY), b"done").context("write native asset deploy marker")?;
    Ok(())
}

fn deploy_lock_path(key: &str) -> PathBuf {
    repo_root().join(format!("target/integration-tests-deploy-{key}.lock"))
}

fn deploy_cache_path(key: &str) -> PathBuf {
    repo_root().join(format!("target/integration-tests-deploy-{key}.json"))
}

/// Held until dropped, so one process deploys `key` while others wait then
/// read the cache.
async fn acquire_deploy_lock(key: &str) -> Result<std::fs::File> {
    let key = key.to_string();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(deploy_lock_path(&key))?;
        file.lock()?;
        std::io::Result::Ok(file)
    })
    .await
    .expect("lock task panicked")
    .context("acquire deploy lock")
}

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests has a parent directory")
        .to_path_buf()
}

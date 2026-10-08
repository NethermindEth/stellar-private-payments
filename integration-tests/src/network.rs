//! A real local Stellar network (`stellar/quickstart`), expected to already
//! be running (see `make integration-tests`), deployed to via the repo's
//! own `deploy.sh`.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_private_payments::types::{
    ContractConfig, Field, GvkAuthoritySetting, GvkMode, NotePublicKey,
};
use tokio::process::Command;

use crate::{keypair::TestKeypair, pool::PoolOptions};

/// Network passphrase `stellar/quickstart --local` always uses.
pub const NETWORK_PASSPHRASE: &str = "Standalone Network ; February 2017";

const RPC_PORT: u16 = 8000;

/// The Stellar CLI's built-in `local` network alias resolves to
/// `http://localhost:8000`, matching the port `make integration-tests` maps.
const STELLAR_CLI_NETWORK: &str = "local";

const KDF_DOMAIN: &str = "tests";

/// A `stellar/quickstart` local network, already running externally.
pub struct LocalNetwork {
    rpc_url: String,
    admin: TestKeypair,
    gvk_authority: GvkAuthoritySetting,
}

#[derive(Serialize, Deserialize)]
struct DeployCacheEntry {
    identity: DeploymentIdentity,
    config: ContractConfig,
}

/// The account a [`LocalNetwork::deploy`] call used, returned alongside its
/// [`ContractConfig`] for later admin-authorized calls.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeploymentIdentity {
    pub admin_secret: String,
    pub gvk_authority: Option<GvkAuthoritySetting>,
}

impl LocalNetwork {
    /// Connect to the local network, waiting until it reports healthy, and
    /// fund a fresh account for this instance's own bootstrap needs.
    pub async fn start() -> Result<Self> {
        let network = Self {
            rpc_url: format!("http://localhost:{RPC_PORT}/rpc"),
            admin: TestKeypair::generate(),
            gvk_authority: GvkAuthoritySetting::generate()?,
        };
        network.wait_healthy().await?;
        network.fund(&network.admin.address()).await?;
        deploy_native_asset(&network.admin.secret()).await?;
        Ok(network)
    }

    pub fn admin(&self) -> &TestKeypair {
        &self.admin
    }

    pub fn gvk_authority(&self) -> &GvkAuthoritySetting {
        &self.gvk_authority
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
                    if body.contains("already funded") {
                        return Ok(());
                    }
                    last_error = format!("{status}: {body}");
                }
                Err(e) => last_error = e.to_string(),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("friendbot funding failed for {address} after {MAX_ATTEMPTS} attempts: {last_error}");
    }

    /// Deploy one pool per entry of `pools` via
    /// `deployments/scripts/deploy.sh`. Coordinated per configuration (see
    /// [`acquire_deploy_lock`]), so concurrent processes deploying the same
    /// pool set share one deployment.
    pub async fn deploy(
        &self,
        max_deposit: u128,
        asp_levels: u32,
        pool_levels: u32,
        pools: &[PoolOptions],
        scope: Option<&str>,
    ) -> Result<(ContractConfig, DeploymentIdentity)> {
        let root = repo_root();

        let native_token_id = if pools.iter().any(|p| p.asset.is_native()) {
            Some(native_asset_contract_id().await?)
        } else {
            None
        };

        let pool_specs: Vec<String> = pools
            .iter()
            .map(|p| p.pool_spec(native_token_id.as_deref()))
            .collect();

        let mut key = format!(
            "{max_deposit}-{asp_levels}-{pool_levels}-{}",
            pool_specs.join(",")
        );
        if let Some(scope) = scope {
            key = format!("{key}-{scope}");
        }
        let _guard = acquire_deploy_lock(&key).await?;

        if let Ok(cached) = std::fs::read(deploy_cache_path(&key))
            && let Ok(entry) = serde_json::from_slice::<DeployCacheEntry>(&cached)
        {
            return Ok((entry.config, entry.identity));
        }

        let deployer = TestKeypair::generate();
        self.fund(&deployer.address()).await?;
        let deployer_secret = deployer.secret();

        let needs_gvk = pools.iter().any(|p| p.gvk_mode != GvkMode::Off);

        let mut command = Command::new(root.join("deployments/scripts/deploy.sh"));
        command
            .arg(STELLAR_CLI_NETWORK)
            .args(["--deployer", &deployer_secret])
            .args(["--asp-levels", &asp_levels.to_string()])
            .args(["--pool-levels", &pool_levels.to_string()])
            .args(["--max-deposit", &max_deposit.to_string()])
            .args(["--kdf-domain", KDF_DOMAIN])
            .current_dir(&root);
        for spec in &pool_specs {
            command.args(["--pool", spec]);
        }

        if needs_gvk {
            let gvk_pubkey_path =
                repo_root().join(format!("target/integration-tests-gvk-authority-{key}.json"));
            std::fs::write(
                &gvk_pubkey_path,
                serde_json::to_vec(&self.gvk_authority.public_key)
                    .context("serialize GVK authority public key")?,
            )
            .context("write GVK authority public key file")?;
            command.args([
                "--gvk-authority-pubkey-file",
                gvk_pubkey_path
                    .to_str()
                    .context("GVK authority pubkey path is not UTF-8")?,
            ]);
        }

        // serialize deploy.sh runs across all keys, not just this one
        let _global_guard = acquire_deploy_lock("global").await?;
        let output = command
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
        let identity = DeploymentIdentity {
            admin_secret: deployer_secret,
            gvk_authority: needs_gvk.then(|| self.gvk_authority.clone()),
        };

        let entry = DeployCacheEntry {
            identity: identity.clone(),
            config: config.clone(),
        };
        std::fs::write(
            deploy_cache_path(&key),
            serde_json::to_vec(&entry).context("serialize deploy cache entry")?,
        )
        .context("write deploy cache")?;
        Ok((config, identity))
    }

    pub async fn establish_trustline(&self, holder_secret: &str, code: &str) -> Result<()> {
        let output = Command::new("stellar")
            .args(["tx", "new", "change-trust"])
            .args(["--source-account", holder_secret])
            .args(["--line", &format!("{code}:{}", self.admin.address())])
            .args(["--network", STELLAR_CLI_NETWORK])
            .output()
            .await
            .context("run stellar tx new change-trust")?;
        if !output.status.success() {
            bail!(
                "stellar tx new change-trust failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    pub async fn send_classic_payment(
        &self,
        dest_addr: &str,
        code: &str,
        amount: u128,
    ) -> Result<()> {
        let output = Command::new("stellar")
            .args(["tx", "new", "payment"])
            .args(["--source-account", &self.admin.secret()])
            .args(["--destination", dest_addr])
            .args(["--asset", &format!("{code}:{}", self.admin.address())])
            .args(["--amount", &amount.to_string()])
            .args(["--network", STELLAR_CLI_NETWORK])
            .output()
            .await
            .context("run stellar tx new payment")?;
        if !output.status.success() {
            bail!(
                "stellar tx new payment failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    pub async fn deploy_asset_sac(&self, code: &str) -> Result<String> {
        let asset = format!("{code}:{}", self.admin.address());
        let output = Command::new("stellar")
            .args(["contract", "asset", "deploy", "--asset", &asset])
            .args(["--source-account", &self.admin.secret()])
            .args(["--network", STELLAR_CLI_NETWORK])
            .output()
            .await
            .context("run stellar contract asset deploy")?;
        if !output.status.success() {
            bail!(
                "stellar contract asset deploy --asset {asset} failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        extract_contract_id(&String::from_utf8_lossy(&output.stdout))
            .context("parse contract id from stellar contract asset deploy output")
    }

    pub async fn insert_asp_membership_leaf(
        &self,
        contract_id: &str,
        admin_secret: &str,
        leaf: Field,
    ) -> Result<()> {
        self.invoke_contract(
            contract_id,
            admin_secret,
            &["insert_leaf", "--leaf", &leaf.to_string()],
        )
        .await
    }

    pub async fn insert_asp_non_membership_leaf(
        &self,
        contract_id: &str,
        admin_secret: &str,
        note_public_key: NotePublicKey,
    ) -> Result<()> {
        let key = Field::try_from_le_bytes(*note_public_key.as_ref())?;
        self.invoke_contract(
            contract_id,
            admin_secret,
            &[
                "insert_leaf",
                "--key",
                &key.to_string(),
                "--value",
                &key.to_string(),
            ],
        )
        .await
    }

    pub async fn delete_asp_non_membership_leaf(
        &self,
        contract_id: &str,
        admin_secret: &str,
        note_public_key: NotePublicKey,
    ) -> Result<()> {
        let key = Field::try_from_le_bytes(*note_public_key.as_ref())?;
        self.invoke_contract(
            contract_id,
            admin_secret,
            &["delete_leaf", "--key", &key.to_string()],
        )
        .await
    }

    async fn invoke_contract(
        &self,
        contract_id: &str,
        admin_secret: &str,
        args: &[&str],
    ) -> Result<()> {
        let output = Command::new("stellar")
            .args(["contract", "invoke", "--id", contract_id])
            .args(["--source-account", admin_secret])
            .args(["--network", STELLAR_CLI_NETWORK])
            .arg("--")
            .args(args)
            .output()
            .await
            .context("run stellar contract invoke")?;
        if !output.status.success() {
            bail!(
                "stellar contract invoke --id {contract_id} -- {} failed ({}):\n{}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
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

async fn native_asset_contract_id() -> Result<String> {
    let output = Command::new("stellar")
        .args(["contract", "id", "asset", "--asset", "native"])
        .args(["--network", STELLAR_CLI_NETWORK])
        .output()
        .await
        .context("run stellar contract id asset --asset native")?;
    if !output.status.success() {
        bail!(
            "stellar contract id asset --asset native failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn extract_contract_id(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|tok| {
            tok.len() == 56 && tok.starts_with('C') && tok.chars().all(char::is_alphanumeric)
        })
        .map(str::to_string)
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

/// Held for a test's entire critical section touching ASP tree state on
/// `contract_id` (leaf mutations and the deposits that prove against its
/// root), so a proof generated by one test sharing a deployed pool can't be
/// invalidated by a concurrent leaf mutation from another (or vice versa).
///
/// The membership tree keeps a history of recent roots and needs no lock. The
/// non-membership tree accepts only its current root.
///
/// Potential improvements:
/// - Consider `serial_test` when main SDK traits become Send + Sync;
pub async fn lock_asp_tree(contract_id: &str) -> Result<std::fs::File> {
    acquire_deploy_lock(&format!("asp-tree-{contract_id}")).await
}

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests has a parent directory")
        .to_path_buf()
}

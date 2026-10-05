//! Shared setup for tests: each test deploys the one pool it needs on the
//! shared network, then opens its own wallet session against it.

use std::path::PathBuf;

use anyhow::{Context, Result};
use stellar_private_payments::{
    Account, CircuitStore, Client, LocalProver, LocalSigner, LocalStorage, PrivatePool,
    types::{ContractConfig, NoteOwnerAddress, PoolConfigEntry, SignerAddress},
    zk::disclosure::find_circuit,
};

use crate::{
    keypair::TestKeypair,
    network::{self, DeploymentIdentity, LocalNetwork, NETWORK_PASSPHRASE},
    pool::PoolOptions,
};

const MAX_DEPOSIT_STROOPS: u128 = 1_000_000_000_000;
const ASP_LEVELS: u32 = 10;
const POOL_LEVELS: u32 = 20;

pub struct TestSession {
    pub account: Account,
    pub wallet: TestKeypair,
    pub identity: DeploymentIdentity,
    pool_contract_ids: Vec<String>,
    storage_path: PathBuf,
}

impl TestSession {
    pub fn pool(&self) -> Result<PrivatePool> {
        self.pool_at(0)
    }

    pub fn pool_at(&self, index: usize) -> Result<PrivatePool> {
        let pool_contract_id = self
            .pool_contract_ids
            .get(index)
            .with_context(|| format!("no deployed pool at index {index}"))?;
        Ok(self.account.pool(pool_contract_id)?)
    }

    /// Another session for the same wallet on the same wallet database, under
    /// `config` (e.g. another `kdf_domain`).
    pub async fn fork(&self, config: ContractConfig) -> Result<TestSession> {
        let network = LocalNetwork::start().await?;
        build_session(
            &network,
            config,
            self.identity.clone(),
            self.wallet.clone(),
            self.storage_path.clone(),
        )
        .await
    }
}

pub async fn deploy_default() -> Result<(ContractConfig, DeploymentIdentity)> {
    deploy(&[PoolOptions::NONE]).await
}

/// Deploy every entry of `pools` together (one `deploy.sh` invocation, so
/// they share ASP membership/non-membership contracts).
pub async fn deploy(pools: &[PoolOptions]) -> Result<(ContractConfig, DeploymentIdentity)> {
    deploy_with_max_deposit(MAX_DEPOSIT_STROOPS, pools).await
}

/// Like [`deploy`], but with an explicit `max_deposit` cap instead of the
/// suite-wide default.
pub async fn deploy_with_max_deposit(
    max_deposit: u128,
    pools: &[PoolOptions],
) -> Result<(ContractConfig, DeploymentIdentity)> {
    let network = LocalNetwork::start().await?;
    network
        .deploy(max_deposit, ASP_LEVELS, POOL_LEVELS, pools, None)
        .await
}

/// Like [`deploy`], but `scope` is folded into the deploy cache key,
/// guaranteeing a deployment private to this scope instead of one shared
/// with any other test using the same `pools`.
pub async fn deploy_scoped(
    pools: &[PoolOptions],
    scope: &str,
) -> Result<(ContractConfig, DeploymentIdentity)> {
    let network = LocalNetwork::start().await?;
    network
        .deploy(
            MAX_DEPOSIT_STROOPS,
            ASP_LEVELS,
            POOL_LEVELS,
            pools,
            Some(scope),
        )
        .await
}

/// Open a new wallet session against an existing deployment.
pub async fn session(
    (config, identity): (ContractConfig, DeploymentIdentity),
) -> Result<TestSession> {
    let network = LocalNetwork::start().await?;
    let wallet = TestKeypair::generate();
    network.fund(&wallet.address()).await?;

    let storage_path = std::env::temp_dir().join(format!(
        "spp-integration-tests-wallet-{}-{}.sqlite",
        std::process::id(),
        wallet.address()
    ));
    let _ = std::fs::remove_file(&storage_path);
    build_session(&network, config, identity, wallet, storage_path).await
}

async fn build_session(
    network: &LocalNetwork,
    config: ContractConfig,
    identity: DeploymentIdentity,
    wallet: TestKeypair,
    storage_path: PathBuf,
) -> Result<TestSession> {
    let pool_entries: Vec<PoolConfigEntry> = config.enabled_pools().cloned().collect();
    let storage =
        LocalStorage::open(storage_path.to_str().context("storage path is not UTF-8")?)?.into();

    let store = CircuitStore::open(network::repo_root().join("target/circuits-artifacts"));
    store
        .ensure()
        .await
        .context("ensure circuit artifacts (run `make circuits` first)")?;

    let mut circuit_artifacts = Vec::new();
    let mut seen_stems = std::collections::HashSet::new();
    for pool_entry in &pool_entries {
        let stem = pool_entry.circuit_stem();
        if seen_stems.insert(stem.to_string()) {
            let artifacts = store
                .artifacts(&stem.to_string())
                .context("load circuit artifacts for a deployed pool")?;
            circuit_artifacts.push((stem, artifacts));
        }
    }
    let disclosure_artifacts = store
        .disclosure_artifacts()
        .context("load disclosure circuit artifacts")?
        .into_iter()
        .map(|(name, artifacts)| {
            find_circuit(name)
                .map(|circuit| (circuit, artifacts))
                .with_context(|| format!("unregistered disclosure circuit: {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let prover = LocalProver::from_all_artifacts(&circuit_artifacts, &disclosure_artifacts)
        .context("init local prover")?
        .into();

    let client = Client::init(network.rpc_url(), storage, prover, config, None)?;

    let signer = LocalSigner::new(
        &wallet.secret(),
        NETWORK_PASSPHRASE,
        SignerAddress::new(wallet.address()),
    )?
    .into();
    let account = client.account(NoteOwnerAddress::new(wallet.address()), signer)?;
    account
        .derive_privacy_keys()
        .await
        .context("derive privacy keys")?;

    Ok(TestSession {
        account,
        wallet,
        identity,
        pool_contract_ids: pool_entries
            .into_iter()
            .map(|e| e.pool_contract_id)
            .collect(),
        storage_path,
    })
}
